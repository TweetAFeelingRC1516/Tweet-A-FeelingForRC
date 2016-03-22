/*	Tweet-A-Feeling ~ Project for RC class
	Copyright (C) 2016  Fabio Gius, Andrea Pasciucco, Giuseppe D'Alpino

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

var LICENSE = '\tTweet-A-Feeling  Copyright (C) 2016  Fabio Gius, Andrea Pasciucco, Giuseppe D\'Alpino\n\tThis program comes with ABSOLUTELY NO WARRANTY.\n\tThis is free software, and you are welcome to redistribute it\n\tunder certain conditions';
console.log(LICENSE);

var express = require('express');
var session = require('express-session');
var mongoStore = require('connect-mongo')(session);
var request = require('request');
var crypto = require('crypto');
var amqp = require('amqplib/callback_api');
var bodyParser = require('body-parser');
var percentEncode = require('oauth-percent-encode');

var KS = require('./Consumer_K-S.json');
var URLS = require('./urls.json');
var CONS_KEY = KS.cons_key;
var CONS_SECRET = KS.cons_secret;
var AUTHORS = 'Fabio Gius, Andrea Pasciucco, Giuseppe D\'Alpino';
var FORBIDDEN_PAGES = ['/_main', '/_profile', '/_buildTweet', '/_charts', '/_userlist', '/_tweets', '/_notifications'];
var API_PAGES = ['/sendTweet', '/delTweet', '/getTweets', '/getUsers', '/getDataset', '/getChart', '/setNotifications', '/getNotifications'];
var FEELINGS = ['Happy', 'Sad', 'Mad', 'Bored', 'Tired', 'Hopeful', 'Worried'];
var TOPICS = ['Study', 'Work', 'Love', 'Sport', 'Hobby', 'Health'];
var USERS = [];
var CHARTS_PAGES = ['pie', 'bar', 'allpieFeelings', 'mypieFeelings', 'allpieTopics', 'mypieTopics', 'allbarFeelings', 'mybarFeelings', 'allbarTopics', 'mybarTopics'];
var HEADERS = {
	'Content-Type': 'application/json',
	'Accept': 'application/json'
};
var app = express();
var EXCHANGE = 'notifications';
var MAX_LENGTH = 123;
app.set('view engine', 'jade');

var genSessionSecret = function() {
	var sequence = crypto.randomBytes(8);
	return sequence.toString('hex');
};

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session( {
	name: 'T-a-F',
	secret: genSessionSecret(),
	/*		RESAVE (explicit to remove warning at startup)
		TRUE:   Save session in database at every request, even if session is not modified (DEFAULT)
		FALSE:  The opposite

		What to set?
		If store implements touch() interface to update session timespan, then 'false' can be used safely.
		It help avoid race-condition issues.

		Our store implements touch(), so false is ok, after defining update interval in store.

		More:
		https://github.com/expressjs/session/blob/master/README.md#resave
		https://github.com/kcbanner/connect-mongo#lazy-session-update
	*/
	resave: false,
	/*		SAVE UNINITIALIZED (explicit to remove warning at startup)
		TRUE:   Forces a new "empty" (not yet modified) session to be saved in store (DEFAULT)
		FALSE:  The opposite, stores session first time when modified

		False helps reduce storage
		
		More:
		https://github.com/expressjs/session/blob/master/README.md#saveuninitialized
	*/
	saveUninitialized: true,
	store: new mongoStore( {
		url: 'mongodb://mongo/tweetafeeling'/*,
		port: 27017*/
	} )
	/* COOKIE
	Set options for cookie, In particulare maxAge.
	See more here:
	https://github.com/expressjs/session/blob/master/README.md#cookie-options
	*/
} ));

app.use(express.static(__dirname + '/static'));

var checkInArray = function(elem) {
	return elem == this;
}

app.use('/_\*', function(req, res, next) {
	console.log('checking \"_\*\" ...');
	if(!FORBIDDEN_PAGES.some(checkInArray, req.baseUrl)) {
		res.status(404).render('404', { title: 'Oh no, not again...',
										stylesheet: '40x.css',
										author: AUTHORS } );
		return;
	}
	var user = req.session.user;
	if(typeof user === 'undefined'){
		// 401 Unauthorized
		// Not compliant with FULL specifications -> "WWW-Authenticate MUST be included in response", but our doesn't!
		// (login status tracked with cookies, not with WWW-Authenticate/Authorization)
		// See https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.2 for full specification of 401 status code
		res.status(401).render('401', { title: 'You cannot pass.',
										stylesheet: '40x.css',
										author: AUTHORS });
		return;
	}
	if(req.baseUrl === '/_buildTweet') {
		next();
		return;
	}
	var notifs = [];
	var tw_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	request.post( {
		url: URLS.api.concat('/getNotifications'),
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error sending \"getNotifications\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body);
		var notifs = body_json.message;
		for(var i = 0; i < notifs.length; i++) {
			notifs[i].date = notifs[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
			req.session.notifications.push(notifs[i]);
		}
		next();
	} );
} );

app.use('/api/\*', function(req, res, next) {
	console.log('checking \"api/\*\" ...');
	var api = req.baseUrl.substring(4);
	if(!API_PAGES.some(checkInArray, api)) {
		var errMess = api.concat(' API doesn\'t exist.');
		res.json( { result: 'error',
					message: errMess } );
		console.log('Exit for api name not defined');
		return;
	}
	if(!checkApiRequiredFields(req)) {
		res.json( { result: 'error',
					message: 'Missing -user- and/or -apiCode- field in request body' } );
		console.log('Exit for missing \"user\" and/or \"apiCode\" field in request body');
		return;
	}
	var userSent = req.body.user;
	if(!checkUser(userSent)) {
		res.json( { result: 'error',
					message: 'Wrong -user- property'} );
		console.log('Exit for wrong \"user\" property');
		return;
	}
	var objStoreQuery_elements = [];
	objStoreQuery_elements.push(createOrionQueryElement('User', 'false', userSent));
	objStoreQuery_body = createOrionQueryBody(objStoreQuery_elements);

	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(objStoreQuery_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t check data' } );
			return;
		}
		var queryRes = JSON.parse(body);
		if(typeof queryRes.contextResponses !== 'undefined') {
			var queryResAttr = queryRes.contextResponses[0].contextElement.attributes;
			var codeSent = req.body.apiCode;
			var isLogged,
				accToken,
				accTokenS;
			for(var i = 0; i < queryResAttr.length; i++) {
				if(queryResAttr[i].name === 'apiCode') {
					if (queryResAttr[i].value !== codeSent) {
						res.json( { result: 'error',
									message: '-apiCode- doesn\'t match -user-' } );
						console.log('Exit for api code not right');
						return;
					}
				}
				if(queryResAttr[i].name === 'logged')
					isLogged = queryResAttr[i].value;
				if(queryResAttr[i].name === 'Access_Token')
					accToken = queryResAttr[i].value;
				if(queryResAttr[i].name === 'Access_Token_S')
					accTokenS = queryResAttr[i].value;
			}
			if(isLogged !== 'true') {
				res.json( { result: 'error',
							message: 'Not Logged. Login via web browser and retry.' } );
				console.log('Exit because user isn\'t logged in');
				return;
			}
			else {
				if(api === '/sendTweet' || api === '/delTweet') {
					var dataSent = {
						'accToken': accToken,
						'accTokenS': accTokenS
					}
					req.dataSent = dataSent;
				}
				next();
			}
		}
		else {
			res.json( { result: 'error',
						message: 'Could not compare data sent with internal data.' } );
			console.log('Exit for error with retrieving user form Orion.');
			return;
		}
	} );
} );

// FUNZIONI AUSILIARIE
var emptyObject = function(obj) {
	return (Object.getOwnPropertyNames(obj).length === 0);
};

var genApiCode = function(user) {
	var sequence = crypto.randomBytes(4);
	var code = sequence.toString('hex');
	return user.concat('-').concat(code);
};

var checkApiRequiredFields = function(param) {
	return !(typeof param.body.user === 'undefined' || typeof param.body.apiCode  === 'undefined');
};

var checkSendTweetFields = function(param) {
	return !(typeof param.body.feeling === 'undefined' || typeof param.body.topic === 'undefined' ||
		typeof param.body.tweet === 'undefined');
};

var checkGetChartFields = function(param) {
	return !(typeof param.body.chart === 'undefined' || typeof param.body.scope === 'undefined');
};

var checkFeeling = function(feeling) {
	return FEELINGS.some(checkInArray, feeling);
};

var checkTopic = function(topic) {
	return TOPICS.some(checkInArray, topic);
};

var checkUser = function(user) {
	return USERS.some(checkInArray, user);
};

var checkChart = function(chart) {
	chart_arr = chart.split('-');
	if(chart_arr.length > 2)
		return false;
	else if(chart_arr.length === 1) {
		return chart_arr[0] === 'Bar';
	}
	else {
		if(chart_arr[0] !== 'Bar' && chart_arr[0] !== 'Pie')
			return false;
		if(!checkTopic(chart_arr[1]) && !checkFeeling(chart_arr[1]) && chart_arr[1] !== 'Feelings' && chart_arr[1] !== 'Topics')
			return false;
		return true;
	}
};

var checkHashTags = function(feeling, topic) {
	return !(!checkFeeling(feeling) || !checkTopic(topic));
};

var checkCompareScope = function(scope) {
	var arr = scope.split('%');
	if(arr.length !== 2)
		return false;
	if(!checkUser(arr[0]) || !checkUser(arr[1]))
		return false;
	if(arr[0] === arr[1])
		return false;
	return true;
}

var checkSetNotif = function(param) {
	return !(typeof param.feelings === 'undefined' && typeof param.topics === 'undefined');
}

var createTweetsList = function(list) {
	var result = [];
	for(var i = 0; i < list.length; i++) {
		var list_attr = list[i].contextElement.attributes;
		var temp_id = list[i].contextElement.id;
		var temp_date,
			temp_author,
			temp_text,
			temp_feeling,
			temp_topic;
		for(var j = 0; j < list_attr.length; j++) {
			if(list_attr[j].name === 'date')
				temp_date = list_attr[j].value;
			if(list_attr[j].name === 'feeling')
				temp_feeling = list_attr[j].value;
			if(list_attr[j].name === 'text') {
				temp_text = list_attr[j].value;
				// using html notation for forbidden characters in Orion -> restore original message
				temp_text = temp_text.replace(/&lt/g, "<").replace(/&gt/g, ">").replace(/&quot/g, "\"").replace(/&#39/g, "\'");
				temp_text = temp_text.replace(/&#61/g, "=").replace(/&#59/g, ";").replace(/&#40/g, "(").replace(/&#41/g, ")").replace(/&#92/g, "\\");
			}
			if(list_attr[j].name === 'topic')
				temp_topic = list_attr[j].value;
			if(list_attr[j].name === 'author')
				temp_author = list_attr[j].value;
		}
		var single_tweet = {
			id: temp_id,
			date: temp_date,
			author: temp_author,
			text: temp_text,
			feeling: temp_feeling,
			topic: temp_topic
		};
		result.push(single_tweet);
	}
	return result;
}

//refine this funcion: include all symbols, include accented letters
var cleanMessage = function(text) {
	var result = ' '.concat(text).concat(' ');
	result = result.replace(/\(| un'| l'| gliel'|\)/g, " ");
	result = result.replace(/\(|\?|\,|\.|:|\;|\(|\)|\'|\"|\=|\!|\^|\/|\\|\<|\>|\_|#|@|\)/g, " ");
	result = result.replace(/\(| il | lo | la | gli | le | the | ma | but | se | it |\)/g, " ");
	result = result.replace(/\(| di | da | in | con | su | per | tra | fra | of | with | on |\)/g, " ");
	result = result.replace(/\(| del | dello | della | degli | delle |\)/g, " ");
	result = result.replace(/\(| al | allo | alla | agli | alle |\)/g, " ");
	result = result.replace(/\(| dal | dallo | dalla | dagli | dalle |\)/g, " ");
	result = result.replace(/\(| sul | sullo | sulla | sugli | sulle |\)/g, " ");
	result = result.replace(/\(| è | é | un | uno | una | an | is | or |\)/g, " ");
	result = result.replace(/ [a-z] /g, " ").replace(/ [a-z] /g, " ");
	result = result.replace(/\(| questo | questa | questi | queste |\)/g, " ");
	result = result.replace(/\(| quello | quella | quelli | quelle |\)/g, " ");
	result = result.replace(/\(| this | these | that | those | if | else | for | in | out |\)/g, " ");
	//result = result.replace(/[0-9]/g, " ");
	//result = result.replace(/\(|£ |\$ |€ | - |\)/g, " ");
	return result;
};

var genDataset = function(messages) {
	var res = {};
	for(var i = 0; i < messages.length; i++) {
		var bare_mess = cleanMessage(messages[i].toLowerCase());
		var bare_arr = bare_mess.split(' ');
		for(var j = 0; j < bare_arr.length; j++) {
			if(typeof res[bare_arr[j]] === 'undefined')
				res[bare_arr[j]] = 1;
			else
				res[bare_arr[j]] += 1;
		}
	}
	delete res[''];
	return res;
};

var genTimestamp = function() {
	return parseInt(Date.now()/1000);
};

var genNonce = function() {
	var sequence = crypto.randomBytes(16);
	var nonce = sequence.toString('hex'); //good enough for us, but it will only have a-f lower case letters
	return nonce;
};

//generate array with fields used for generating a signature for twitter's REST calls
var genParamArray = function(nonce, timestamp) {
	var cons_key_k = encodeURIComponent('oauth_consumer_key');
	var cons_key_v = encodeURIComponent(CONS_KEY);
	var cons_key_s = cons_key_k.concat('=').concat(cons_key_v);
	var nonce_k = encodeURIComponent('oauth_nonce');
	var nonce_v = encodeURIComponent(nonce);
	var nonce_s = nonce_k.concat('=').concat(nonce_v);
	var sign_method_k = encodeURIComponent('oauth_signature_method');
	var sign_method_v = encodeURIComponent('HMAC-SHA1');
	var sign_method_s = sign_method_k.concat('=').concat(sign_method_v);
	var timestamp_k = encodeURIComponent('oauth_timestamp');
	var timestamp_v = encodeURIComponent(timestamp);
	var timestamp_s = timestamp_k.concat('=').concat(timestamp_v);
	var version_k = encodeURIComponent('oauth_version');
	var version_v = encodeURIComponent('1.0');
	var version_s = version_k.concat('=').concat(version_v);

	return [cons_key_s, nonce_s, sign_method_s, timestamp_s, version_s];
}

//generate a signature for generic REST calls
var genOauthSign = function(reqMethod, url, nonce, timestamp, more, token_secret) {
	var method = reqMethod;
	var url_enc = encodeURIComponent(url);

	var paramArray = genParamArray(nonce, timestamp);
	for(var i = 0; i < more.length; i++) {
		var more_k = encodeURIComponent(more[i][0]);
		if(more[i][0] === 'status')
			var more_v = more[i][1];
		else
			var more_v = encodeURIComponent(more[i][1]);
		paramArray.push(more_k.concat('=').concat(more_v));
	}
	paramArray.sort();

	var paramString = paramArray.join('&');
	var paramString_enc = encodeURIComponent(paramString);
	var signBase_Str = method.concat('&').concat(url_enc).concat('&').concat(paramString_enc);
	var signKey = encodeURIComponent(CONS_SECRET).concat('&').concat(encodeURIComponent(token_secret));
	
	var hmac = crypto.createHmac('sha1', signKey).update(signBase_Str);
	var res = hmac.digest('base64');
	return res;
}

//generates value of 'Authorization' field in HTTP header
var genAuthString = function(nonce, signature, timestamp, more) {
	var params = [];
	var consKey_Str_k = encodeURIComponent('oauth_consumer_key');
	var consKey_Str_v = encodeURIComponent(CONS_KEY);
	params.push(consKey_Str_k.concat('=\"').concat(consKey_Str_v).concat('\"'));
	var nonce_Str_k = encodeURIComponent('oauth_nonce');
	var nonce_Str_v = encodeURIComponent(nonce);
	params.push(nonce_Str_k.concat('=\"').concat(nonce_Str_v).concat('\"'));
	var signature_Str_k = encodeURIComponent('oauth_signature');
	var signature_Str_v = encodeURIComponent(signature);
	params.push(signature_Str_k.concat('=\"').concat(signature_Str_v).concat('\"'));
	var sign_meth_Str_k = encodeURIComponent('oauth_signature_method');
	var sign_meth_Str_v = encodeURIComponent('HMAC-SHA1');
	params.push(sign_meth_Str_k.concat('=\"').concat(sign_meth_Str_v).concat('\"'));
	var timestamp_Str_k = encodeURIComponent('oauth_timestamp');
	var timestamp_Str_v = encodeURIComponent(timestamp);
	params.push(timestamp_Str_k.concat('=\"').concat(timestamp_Str_v).concat('\"'));
	var version_Str_k = encodeURIComponent('oauth_version');
	var version_Str_v = encodeURIComponent('1.0');
	params.push(version_Str_k.concat('=\"').concat(version_Str_v).concat('\"'));
	var more_k = encodeURIComponent(more[0]);
	var more_v = encodeURIComponent(more[1]);
	params.push(more_k.concat('=\"').concat(more_v).concat('\"'));
	params.sort();

	var res1 = 'OAuth ';
	var res2 = params.join(', ');
	return res1.concat(res2);
}

// attribute to be inserted in object to be stored in orion
var createOrionAttribute = function(attrName, attrType, attrValue) {
	var attribute = {
		'name': attrName,
		'type': attrType,
		'value': attrValue
	};
	return attribute;
};

// object to be sent to orion
var createOrionElement = function(type, isPattern, id, attr) {
	var elem = {
		'type': type,
		'isPattern': isPattern,
		'id': id,
		'attributes': attr
	};
	return elem;
};

// body for orion "updateContext" request
var createOrionBody = function(elements, action) {
	var body = {
		'contextElements': elements,
		'updateAction': action
	};
	return body;
};

var createOrionQueryElement = function(type, isPattern, id) {
	var elem = {
		'type': type,
		'isPattern': isPattern,
		'id': id
	};
	return elem;
};

var createOrionQueryBody = function(elements) {
	var body = {
		'entities': elements
	};
	return body;
};

// ROUTING FUNCTIONS
app.get('/', function(req, res) {
	if(typeof req.session.user !== 'undefined')
		res.redirect('/_main');
	else {
		console.log('***** Someone has just gotten here! *****');
		res.render('login', { title: '~ Tweet-A-Feeling ~',
								stylesheet: 'login.css',
								author: AUTHORS } );
	}
} );

app.get('/42', function(req, res) {
	res.render('42', { title: 'Don\'t panic!',
						stylesheet: '42.css',
						author: 'Deep Thought' } );
} );

app.get('/whatIS', function(req, res) {
	res.render('whatIS', { title: '~ Tweet-A-what-IS-this? ~',
							stylesheet: 'whatIS.css',
							author: AUTHORS } );
} );

app.get('/about', function(req, res) {
	res.render('about', { title: '~ Tweet-A-bout ~',
							stylesheet: 'about.css',
							author: AUTHORS } );
} );

app.get('/login', function(req, res) {
	// already logged
	if(typeof req.session.user !== 'undefined')
		res.redirect('/_main');
	// not possible -> error -> destroy and restart empty session
	else if(typeof req.session.token !== 'undefined' || typeof req.session.tokenR !== 'undefined') {
		req.session.destroy();
		res.redirect('/');
	}
	else {
		console.log("Pagina di login");	
		var rt_url = URLS.oauth_req_token;
		var rt_nonce = genNonce();
		var rt_timestamp = genTimestamp();
		var params = [['oauth_callback', URLS.oauth_callback]];
		var rt_signature = genOauthSign('POST', rt_url, rt_nonce, rt_timestamp, params, '');
		var rt_authString = genAuthString(rt_nonce, rt_signature, rt_timestamp, ['oauth_callback', URLS.oauth_callback]);
		var rt_headers = {'Authorization': rt_authString };

		request.post( {
			headers: rt_headers,
			url: rt_url
		}, function(error, response, body) {
			if(error) {
				console.log('Error sending request (Request Token)');
				res.sendStatus(500);
				return;
			}
			if(body.substring(2,8) === 'errors') {
				console.log('Error returned from Twitter');
				res.sendStatus(500);
				return;
			}
			var body_Arr = body.split('&');
			var token_Arr = body_Arr[0].split('=');
			var token_secret_Arr = body_Arr[1].split('=');
			req.session.tokenR = token_Arr[1];
			req.session.secretR = token_secret_Arr[1];

			var redirect = URLS.twitter_login_redirect.concat('?');
			redirect = redirect.concat('oauth_token=').concat(req.session.tokenR);
			redirect = redirect.concat('&').concat('force_login=true');
			console.log('redirecting to Twitter...');
			res.redirect(redirect);
		} );
	}
} );

app.get('/return', function(req, res) {
	// already logged
	if(typeof req.session.user !== 'undefined')
		res.redirect('/_main');
	// not possible -> error -> destroy session and restart empty one
	else if(typeof req.session.token !== 'undefined')
		req.session.destroy();
	// login procedure not started yet -> redirect to first page
	else if(typeof req.session.tokenR === 'undefined')
		res.redirect('/');
	else {
		console.log('Login effettuato, conversione \"Request Token\" in \"Access Token\"');	
		if(typeof req.query.denied !== 'undefined') {
			req.session.destroy();
			res.redirect('/');
			return;
		}
		else {
			var at_oauth_token = req.query.oauth_token;
			if(at_oauth_token !== req.session.tokenR) {
				req.session.destroy();
				res.redirect('/');
				return;
			}
			var at_oauth_verifier = req.query.oauth_verifier;	
			var at_url = URLS.oauth_acc_token;
			var at_nonce = genNonce();
			var at_timestamp = genTimestamp();
			var params = [];
			params.push(['oauth_token', req.session.tokenR]);
			params.push(['oauth_verifier', at_oauth_verifier]);
			var at_signature = genOauthSign('POST', at_url, at_nonce, at_timestamp, params, req.session.secretR);
			var at_authString = genAuthString(at_nonce, at_signature, at_timestamp, ['oauth_token', req.session.tokenR]);
			var at_headers = {'Authorization': at_authString,
								'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' };
			var at_body = 'oauth_verifier='.concat(at_oauth_verifier);
	
			request.post( {
				headers: at_headers,
				url: at_url,
				body: at_body
			}, function(error, response, body) {
				if(error) {
					console.log('Error sending request (Access Token)');
					req.session.destroy();
					res.sendStatus(500);
					return;
				}
				if(body.substring(2,8) === 'errors') {
					console.log('Error returned from Twitter');
					req.session.destroy();
					res.sendStatus(500);
					return;
				}
				var body_Arr = body.split('&');
				var token_Arr = body_Arr[0].split('=');
				var token_secret_Arr = body_Arr[1].split('=');
				req.session.token = token_Arr[1];
				req.session.secret = token_secret_Arr[1];

				var verify_cred_url = URLS.verify_credentials;
				var cred_nonce = genNonce();
				var cred_timestamp = genTimestamp();
				var params = [['oauth_token', req.session.token]];
				var cred_signature = genOauthSign('GET', verify_cred_url, cred_nonce, cred_timestamp, params, req.session.secret);
				var cred_authString = genAuthString(cred_nonce, cred_signature, cred_timestamp, ['oauth_token', req.session.token]);
				var verify_cred_headers = {'Authorization': cred_authString };

				request.get( {
					headers: verify_cred_headers,
					url: verify_cred_url
				}, function(error, response, body) {
					if(error) {
						console.log('Error sending request (Verify Credentials)');
						req.session.destroy();
						res.sendStatus(500);
						return;
					}
					var json_body = JSON.parse(body);

					if(typeof json_body.errors !== 'undefined') {
						console.log('Error returned from Twitter');
						req.session.destroy();
						res.sendStatus(500);
						return;
					}
					var user = json_body.screen_name;
					var avatar = json_body.profile_image_url;
					console.log('***** Logged: ' + user + ' *****');

					//user already in object store?
					var objStoreQuery_elements = [];
					objStoreQuery_elements.push(createOrionQueryElement('User', 'false', user));
					objStoreQuery_body = createOrionQueryBody(objStoreQuery_elements);

					request.post( {
						headers: HEADERS,
						url: URLS.orion_queryContext,
						body: JSON.stringify(objStoreQuery_body)
					}, function(error, response, body) {
						if(error) {
							console.log('Error sending query request to Orion');
							req.session.destroy();
							res.sendStatus(500);
							return;
						}
						var queryRes = JSON.parse(body);
						if(typeof queryRes.contextResponses === 'undefined') {
							if(queryRes.errorCode.code === '404') {
								console.log('***** ' + user + '\'s first login *****');
								//no controllo già loggato, se è il primo login non può essere loggato altrove
								//si presuppone no primo login contemporaneo da due browser diversi per lo stesso utente
								var notif_w = { "feelings": [],
												"topics": [] };
								req.session.apiCode = genApiCode(user);

								var objStoreUpdate_attributes = [];
								objStoreUpdate_attributes.push(createOrionAttribute('username', 'string', user));
								objStoreUpdate_attributes.push(createOrionAttribute('logged', 'boolean', 'true'));
								objStoreUpdate_attributes.push(createOrionAttribute('Access_Token', 'string', req.session.token));
								objStoreUpdate_attributes.push(createOrionAttribute('Access_Token_S', 'string', req.session.secret));
								objStoreUpdate_attributes.push(createOrionAttribute('notif_wanted', 'object', notif_w));								
								objStoreUpdate_attributes.push(createOrionAttribute('apiCode', 'string', req.session.apiCode));
								var objStoreUpdate_elements = [];
								objStoreUpdate_elements.push(createOrionElement('User', 'false', user, objStoreUpdate_attributes));
								var objStoreUpdate_body = createOrionBody(objStoreUpdate_elements, 'APPEND');
	
								request.post( {
									headers: HEADERS,
									url: URLS.orion_updateContext,
									body: JSON.stringify(objStoreUpdate_body)
								}, function(error, response, body) {
									if(error) {
										console.log('Error sending update request to Orion');
										req.session.destroy();
										res.sendStatus(500);
										return;
									}
									if(typeof JSON.parse(body).contextResponses !== 'undefined') {
										USERS.push(user);
										req.session.user = user;
										req.session.notifications = [];
										req.session.avatar = avatar;
										res.render('message', { title: '~ Tweet-A-LoggedIn ~',
																stylesheet: 'message.css',
																author: AUTHORS,
																destination: '/_main',
																text: 'Logged in successfully.',
																button: 'Go to Main Page' } );
									}
									else {
										console.log('Error while inserting user into Orion.');
										req.session.destroy();
										res.sendStatus(500);
										return;

									}
								} );
							}
							else {
								console.log('Error while querying Orion.');
								req.session.destroy();
								res.sendStatus(500);
								return;
							}
						}
						else {
							console.log('***** No first login *****');
							var queryResAttr = queryRes.contextResponses[0].contextElement.attributes;
							for(var i = 0; i < queryResAttr.length; i++) {
								if(queryResAttr[i].name === 'apiCode')
									req.session.apiCode = queryResAttr[i].value;
								if(queryResAttr[i].name === 'logged' && queryResAttr[i].value === 'true') {
									console.log('User ' + user + ' is already logged in another browser or device.');
									req.session.destroy();
									res.sendStatus(500);
									return;
								}
							}
							var objStoreUpdate_attributes = [];
							objStoreUpdate_attributes.push(createOrionAttribute('logged', 'boolean', 'true'));
							objStoreUpdate_attributes.push(createOrionAttribute('Access_Token', 'string', req.session.token));
							objStoreUpdate_attributes.push(createOrionAttribute('Access_Token_S', 'string', req.session.secret));
							var objStoreUpdate_elements = [];
							objStoreUpdate_elements.push(createOrionElement('User', 'false', user, objStoreUpdate_attributes));
							var objStoreUpdate_body = createOrionBody(objStoreUpdate_elements, 'UPDATE');

							request.post( {
								headers: HEADERS,
								url: URLS.orion_updateContext,
								body: JSON.stringify(objStoreUpdate_body)
							}, function(error, response, body) {
								if(error) {
									console.log('Error sending update request to Orion');
									req.session.destroy();
									res.sendStatus(500);
									return;
								}
								if(typeof JSON.parse(body).contextResponses !== 'undefined') {
									req.session.user = user;
									req.session.notifications = [];
									req.session.avatar = avatar;
									res.render('message', { title: '~ Tweet-A-LoggedIn ~',
															stylesheet: 'message.css',
															author: AUTHORS,
															destination: '/_main',
															text: 'Logged in successfully.',
															button: 'Go to Main Page' } );
								}
								else {
									console.log('Error updating user in Orion.')
									req.session.destroy();
									res.sendStatus(500);
									return;
								}
							} );
						}
					} );					
				} );
			} );
		}
	}
} );

app.get('/_main', function(req, res) {
	console.log('/_main page');
	var tw_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	request.post( {
		url: URLS.api.concat('/getTweets'),
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getTweets\" request');
			res.sendStatus(500);
			return;
		} //no check for error response: we know the request is well built, there should't be errors
		var body_json = JSON.parse(body);
		var tweets = body_json.message.slice(0, 20);
		for(var i = 0; i < tweets.length; i++)
			tweets[i].date = tweets[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
		res.render('main', { title: '~ Tweet-A-Feeling ~',
								stylesheet: 'main.css',
								author: AUTHORS,
								user: req.session.user,
								tweets: tweets,
								feelings: FEELINGS,
								topics: TOPICS,
								n_count: req.session.notifications.length } );
	} );
} );

app.get('/_tweets', function(req, res) {
	console.log('/_tweets page');
	var tw_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	request.post( {
		url: URLS.api.concat('/getTweets'),
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getTweets\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body);
		var tweets = body_json.message;
		for(var i = 0; i < tweets.length; i++)
			tweets[i].date = tweets[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
		res.render('tweets', { title: '~ Tweet-A-Feeling ~',
								stylesheet: 'tweets.css',
								author: AUTHORS,
								user: req.session.user,
								tweets: tweets,
								feelings: FEELINGS,
								topics: TOPICS,
								n_count: req.session.notifications.length } );
	} );
} );

app.post('/_tweets', function(req, res) {
	console.log('/_tweets page');
	var del_body = {
		apiCode: req.session.apiCode,
		user: req.session.user,
		id: req.body.id
	};
	request.del( {
		url: URLS.api.concat('/delTweet'),
		headers: HEADERS,
		body: JSON.stringify(del_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"delTweet\" request');
			res.sendStatus(500);
			return;
		}
		if(JSON.parse(body).result === 'success') {
			var tw_body = {
				apiCode: req.session.apiCode,
				user: req.session.user
			};
			request.post( {
				url: URLS.api.concat('/getTweets'),
				headers: HEADERS,
				body: JSON.stringify(tw_body)
			}, function(error, response, body) {
				if(error) {
					console.log('Error in sending \"getTweets\" request');
					res.sendStatus(500);
					return;
				}
				var body_json = JSON.parse(body);
				var tweets = body_json.message;
				for(var i = 0; i < tweets.length; i++)
					tweets[i].date = tweets[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
				res.render('tweets', { title: '~ Tweet-A-Feeling ~',
										stylesheet: 'tweets.css',
										author: AUTHORS,
										user: req.session.user,
										tweets: tweets,
										feelings: FEELINGS,
										topics: TOPICS,
										n_count: req.session.notifications.length } );
			} );
		}
		else {
			console.log('Error returned from API \"delTweet\"');
			res.sendStatus(500);
		}
	} );
} );

app.get('/_notifications', function(req, res) {
	console.log('/_notifications page');
	var notifs = req.session.notifications.reverse();
	req.session.notifications = [];
	res.render('notifications', { title: '~ Tweet-A-Feeling ~',
									stylesheet: 'notifications.css',
									author: AUTHORS,
									user: req.session.user,
									notifs: notifs,
									feelings: FEELINGS,
									topics: TOPICS,
									n_count: req.session.notifications.length } );
} );

app.post('/_buildTweet', function(req, res) {
	console.log('Building Tweet...')
	var sendTw_body = {};
	sendTw_body['apiCode'] = req.session.apiCode;
	sendTw_body['user'] = req.session.user;
	sendTw_body['tweet'] = req.body.tweet;
	sendTw_body['feeling'] = req.body.feeling;
	sendTw_body['topic'] = req.body.topic;
	request.post( {
		url: URLS.api.concat('/sendTweet'),
		headers: HEADERS,
		body: JSON.stringify(sendTw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"sendTweet\" request');
			res.sendStatus(500);
			return;
		}
		body_json = JSON.parse(body);
		//I check for errors: while the request is well built the text of the tweet
		//may generate errors due to invalid characters
		if(body_json.result === 'error') {
			res.sendStatus(400);
			return;
		}
		res.redirect('/_main');
	} );
} );

app.get('/_charts', function(req, res) {
	console.log('/_charts page');
	res.render('charts', { title: '~ Tweet-A-Charts ~',
							stylesheet: 'charts.css',
							author: AUTHORS,
							user: req.session.user,
							charts: [],
							n_count: req.session.notifications.length } );
} );

app.post('/_charts', function(req, res) {
	console.log('/_charts page');
	//in case if inserting control 'typeof req.body.page !== undefined' then uncomment below
	var page = req.body.page;
	console.log('Wanted page: ' + page);
	//useless control? page arrives form our page (given nobody manually builds a message)
	//if(!CHARTS_PAGES.some(checkInArray, page)) {
	//	res.sendStatus(400);
	//	return;
	//}
	var chart_body = {
		apiCode: req.session.apiCode,
		user: req.session.user,
		scope: '',
		chart: ''
	};
	var charts = [];

	var callChart = function(call_body, scope_arr, chart_arr, cont) {
		console.log('***** ITERATION N° ' + cont + ' *****');
		call_body['scope'] = scope_arr[cont];
		call_body['chart'] = chart_arr[cont];

		request.post( {
			url: URLS.api.concat('/getChart'),
			headers: HEADERS,
			body: JSON.stringify(call_body),
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending \"getChart\" request');
				res.sendStatus(500);
				return;
			}
			var body_json = JSON.parse(body);
			/*if(body_json.result === 'error') {
				res.sendStatus(400);
				return;
			}*/
			charts.push(body_json.message);

			if(++cont < scope_arr.length)
				callChart(call_body, scope_arr, chart_arr, cont);
			else
				res.render('charts', { title: '~ Tweet-A-Charts ~',
										stylesheet: 'charts.css',
										author: AUTHORS,
										user: req.session.user,
										charts: charts,
										n_count: req.session.notifications.length } );
		} );
	};
	var scopeArr = [];
	var chartArr = [];

	if(page === CHARTS_PAGES[0]) {
		scopeArr = ['%%', '%%', req.session.user, req.session.user];
		chartArr = ['Pie-Feelings', 'Pie-Topics', 'Pie-Feelings', 'Pie-Topics'];
	}
	if(page === CHARTS_PAGES[1]) {
		scopeArr = ['%%', req.session.user];
		chartArr = ['Bar', 'Bar'];
	}
	if(page === CHARTS_PAGES[2]) {
		for(var i = 0; i < FEELINGS.length; i++) {
			var chartElem = 'Pie-'.concat(FEELINGS[i]);
			scopeArr.push('%%');
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[3]) {
		for(var i = 0; i < FEELINGS.length; i++) {
			var chartElem = 'Pie-'.concat(FEELINGS[i]);
			scopeArr.push(req.session.user);
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[4]) {
		for(var i = 0; i < TOPICS.length; i++) {
			var chartElem = 'Pie-'.concat(TOPICS[i]);
			scopeArr.push('%%');
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[5]) {
		for(var i = 0; i < TOPICS.length; i++) {
			var chartElem = 'Pie-'.concat(TOPICS[i]);
			scopeArr.push(req.session.user);
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[6]) {
		for(var i = 0; i < FEELINGS.length; i++) {
			var chartElem = 'Bar-'.concat(FEELINGS[i]);
			scopeArr.push('%%');
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[7]) {
		for(var i = 0; i < FEELINGS.length; i++) {
			var chartElem = 'Bar-'.concat(FEELINGS[i]);
			scopeArr.push(req.session.user);
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[8]) {
		for(var i = 0; i < TOPICS.length; i++) {
			var chartElem = 'Bar-'.concat(TOPICS[i]);
			scopeArr.push('%%');
			chartArr.push(chartElem);
		}
	}
	if(page === CHARTS_PAGES[9]) {
		for(var i = 0; i < TOPICS.length; i++) {
			var chartElem = 'Bar-'.concat(TOPICS[i]);
			scopeArr.push(req.session.user);
			chartArr.push(chartElem);
		}
	}
	callChart(chart_body, scopeArr, chartArr, 0);
} );

app.get('/_profile', function(req, res) {
	console.log(req.session.user + ' has requested his userpage...');
	var tw_body = {
		apiCode: req.session.apiCode,
		user: req.session.user,
		author: req.session.user
	};
	request.post( {
		url: URLS.api.concat('/getTweets'),
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getTweets\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body);
		/*if(body_json.result === 'error') {
			res.sendStatus(400);
			return;
		}*/
		var tweets = body_json.message.slice(0, 10);
		for(var i = 0; i < tweets.length; i++)
			tweets[i].date = tweets[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
		var queryUser_elements = [];
		queryUser_elements.push(createOrionQueryElement('User', 'false', req.session.user));
		queryUser_body = createOrionQueryBody(queryUser_elements);
		request.post( {
			headers: HEADERS,
			url: URLS.orion_queryContext,
			body: JSON.stringify(queryUser_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending query request to Orion');
				res.sendStatus(500);
				return;
			}
			var queryRes = JSON.parse(body);
			//errorCode 404 NOT possible
			if(typeof queryRes.contextResponses === 'undefined') {
				res.sendStatus(500);
				console.log('Exit because Couldn\'t retrieve data.');
				return;
			}
			var contextRes = queryRes.contextResponses;
			var contextRes_attr = contextRes[0].contextElement.attributes;
			var notif_settings;
			for(var i = 0; i < contextRes_attr.length; i++) {
				if(contextRes_attr[i].name === 'notif_wanted') {
					notif_settings = contextRes_attr[i].value;
					break;
				}
			}
			var notif_feelings = [],
				notif_topics = [];
			if(!emptyObject(notif_settings.feelings))
				notif_feelings = notif_settings.feelings;
			if(!emptyObject(notif_settings.topics))
				notif_topics = notif_settings.topics;

			var feelings_list = [];
			for(var i = 0; i < FEELINGS.length; i++) {
				var elem = [];
				elem.push(FEELINGS[i]);
				if(notif_feelings.length !== 0 && notif_feelings.some(checkInArray, FEELINGS[i]))
					elem.push(true);
				else
					elem.push(false);
				feelings_list.push(elem);
			}
			var topics_list = [];
			for(var i = 0; i < TOPICS.length; i++) {
				var elem = [];
				elem.push(TOPICS[i]);
				if(notif_topics.length !== 0 && notif_topics.some(checkInArray, TOPICS[i]))
					elem.push(true);
				else
					elem.push(false);
				topics_list.push(elem);
			}
			res.render('profile', { title: '~ Tweet-A-Profile ~',
									stylesheet: 'profile.css',
									author: AUTHORS,
									user: req.session.user,
									apiCode: req.session.apiCode,
									tweets: tweets,
									feelings: feelings_list,
									topics: topics_list,
									avatar: req.session.avatar,
									n_count: req.session.notifications.length } );
		} );
	} );
} );

app.post('/_profile', function(req, res) {
	console.log(req.session.user + ' wants to update his notification settings...');
	var set_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	var unset_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	var tw_body = {
		apiCode: req.session.apiCode,
		user: req.session.user,
		author: req.session.user
	};
	var setFeelings = [],
		setTopics = [],
		unsetFeelings = [],
		unsetTopics = [];

	if(typeof req.body.feelings === 'undefined') {
		unsetFeelings = FEELINGS;
		unset_body['feelings'] = unsetFeelings;
	}
	else {
		if(typeof req.body.feelings === 'string')
			setFeelings.push(req.body.feelings);
		else
			setFeelings = req.body.feelings;
		set_body['feelings'] = setFeelings;
		if(setFeelings.length < FEELINGS.length) {
			for(var i = 0; i < FEELINGS.length; i++) {
				if(!setFeelings.some(checkInArray, FEELINGS[i]))
					unsetFeelings.push(FEELINGS[i]);
			}
			unset_body['feelings'] = unsetFeelings;
		}
	}
	if(typeof req.body.topics === 'undefined') {
		unsetTopics = TOPICS;
		unset_body['topics'] = unsetTopics;
	}
	else {
		if(typeof req.body.topics === 'string')
			setTopics.push(req.body.topics);
		else
			setTopics = req.body.topics;
		set_body['topics'] = setTopics;
		if(setTopics.length < TOPICS.length) {
			for(var i = 0; i < TOPICS.length; i++) {
				if(!setTopics.some(checkInArray, TOPICS[i]))
					unsetTopics.push(TOPICS[i]);
			}
			unset_body['topics'] = unsetTopics;
		}
	}
	var set_case;
	if(setFeelings.length === 0 && setTopics.length === 0)
		set_case = 0; //only unset
	else if(unsetFeelings.length === 0 && unsetTopics.length === 0)
		set_case = 1; //only set
	else
		set_case = 3;
	request.post( {
		url: URLS.api.concat('/getTweets'),
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getTweets\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body)
		/*if(body_json.result === 'error') {
			res.sendStatus(400);
			return;
		}*/
		var tweets = body_json.message.slice(0, 10);
		for(var i = 0; i < tweets.length; i++)
			tweets[i].date = tweets[i].date.replace(/\+[0-9][0-9][0-9][0-9] /g, "");
		switch (set_case) {
			case 0:
				request.del( {
					url: URLS.api.concat('/setNotifications'),
					headers: HEADERS,
					body: JSON.stringify(unset_body)
				}, function(error, response, body) {
					if(error) {
						console.log('Error in sending \"setNotifications\" request');
						res.sendStatus(500);
						return;
					}
					/*if(body_json.result === 'error') {
						res.sendStatus(400);
						return;
					}*/
					var feelings_list = [];
					for(var i = 0; i < FEELINGS.length; i++)
						feelings_list.push([FEELINGS[i], false]);
					var topics_list = [];
					for(var i = 0; i < TOPICS.length; i++)
						topics_list.push([TOPICS[i], false]);
					res.render('profile', { title: '~ Tweet-A-Profile ~',
											stylesheet: 'profile.css',
											author: AUTHORS,
											user: req.session.user,
											apiCode: req.session.apiCode,
											tweets: tweets,
											feelings: feelings_list,
											topics: topics_list,
											avatar: req.session.avatar,
											n_count: req.session.notifications.length } );
				} );
				break;
			case 1:
				request.post( {
					url: URLS.api.concat('/setNotifications'),
					headers: HEADERS,
					body: JSON.stringify(set_body)
				}, function(error, response, body) {
					if(error) {
						console.log('Error in sending \"setNotifications\" request');
						res.sendStatus(500);
						return;
					}
					/*if(body_json.result === 'error') {
						res.sendStatus(400);
						return;
					}*/
					var feelings_list = [];
					for(var i = 0; i < FEELINGS.length; i++)
						feelings_list.push([FEELINGS[i], true]);
					var topics_list = [];
					for(var i = 0; i < TOPICS.length; i++)
						topics_list.push([TOPICS[i], true]);
					res.render('profile', { title: '~ Tweet-A-Profile ~',
											stylesheet: 'profile.css',
											author: AUTHORS,
											user: req.session.user,
											apiCode: req.session.apiCode,
											tweets: tweets,
											feelings: feelings_list,
											topics: topics_list,
											avatar: req.session.avatar,
											n_count: req.session.notifications.length } );
				} );
				break;
			case 3:
				request.post( {
					url: URLS.api.concat('/setNotifications'),
					headers: HEADERS,
					body: JSON.stringify(set_body)
				}, function(error, response, body) {
					if(error) {
						console.log('Error in sending unset request');
						res.sendStatus(500);
						return;
					}
					/*if(body_json.result === 'error') {
						res.sendStatus(400);
						return;
					}*/
					request.del( {
						url: URLS.api.concat('/setNotifications'),
						headers: HEADERS,
						body: JSON.stringify(unset_body)
					}, function(error, response, body) {
						if(error) {
							console.log('Error in sending set request (some unsetted)');
							res.sendStatus(500);
							return;
						}
						/*if(body_json.result === 'error') {
							res.sendStatus(400);
							return;
						}*/
						var feelings_list = [];
						for(var i = 0; i < FEELINGS.length; i++) {
							var elem = [];
							elem.push(FEELINGS[i]);
							if(setFeelings.length !== 0 && setFeelings.some(checkInArray, FEELINGS[i]))
								elem.push(true);
							else
								elem.push(false);
							feelings_list.push(elem);
						}			
						var topics_list = [];
						for(var i = 0; i < TOPICS.length; i++) {
							var elem = [];
							elem.push(TOPICS[i]);
							if(setTopics.length !== 0 && setTopics.some(checkInArray, TOPICS[i]))
								elem.push(true);
							else
								elem.push(false);
							topics_list.push(elem);
						}
						res.render('profile', { title: '~ Tweet-A-Profile ~',
												stylesheet: 'profile.css',
												author: AUTHORS,
												user: req.session.user,
												apiCode: req.session.apiCode,
												tweets: tweets,
												feelings: feelings_list,
												topics: topics_list,
												avatar: req.session.avatar,
												n_count: req.session.notifications.length } );
					} );
				} );
				break;
		}
	} );
} );

app.get('/_userlist', function(req, res) {
	console.log(req.session.user + ' has requested userlist page...');
	var users_body = {
		apiCode: req.session.apiCode,
		user: req.session.user
	};
	request.post( {
		url: URLS.api.concat('/getUsers'),
		headers: HEADERS,
		body: JSON.stringify(users_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getUsers\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body);
		var userlist = body_json.message;
		res.render('userlist', { title: '~ Tweet-A-Userlist ~',
								stylesheet: 'userlist.css',
								author: AUTHORS,
								user: req.session.user,
								userlist: userlist,
								feelings: FEELINGS,
								topics: TOPICS,
								n_count: req.session.notifications.length } );
	} );
} );

app.post('/_userlist', function(req, res) {
	console.log('Building compare chart...');
	var chart_body = {
		apiCode: req.session.apiCode,
		user: req.session.user,
		chart: req.body.chart,
		scope: req.body.scope
	};
	request.post( {
		url: URLS.api.concat('/getChart'),
		headers: HEADERS,
		body: JSON.stringify(chart_body),
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending \"getChart\" request');
			res.sendStatus(500);
			return;
		}
		var body_json = JSON.parse(body);
		if(body_json.result === 'error') {
			res.sendStatus(400);
		}
		var chart = body_json.message;
		var users_body = {
			apiCode: req.session.apiCode,
			user: req.session.user
		};
		request.post( {
			url: URLS.api.concat('/getUsers'),
			headers: HEADERS,
			body: JSON.stringify(users_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending \"getUsers\" request');
				res.sendStatus(500);
				return;
			}
			var body_json = JSON.parse(body);
			var userlist = body_json.message;
			res.render('userlist', { title: '~ Tweet-A-Userlist ~',
									stylesheet: 'userlist.css',
									author: AUTHORS,
									user: req.session.user,
									userlist: userlist,
									feelings: FEELINGS,
									topics: TOPICS,
									chart: chart,
									n_count: req.session.notifications.length } );
		} );
	} );
} );

app.get('/logout', function(req, res) {
	if(typeof req.session.user === 'undefined')
		res.redirect('/');
	else {
		var objStore_attributes = [];
		objStore_attributes.push(createOrionAttribute('logged', 'boolean', 'false'));
		objStore_attributes.push(createOrionAttribute('Access_Token', 'string', ''));
		objStore_attributes.push(createOrionAttribute('Access_Token_S', 'string', ''));
		var objStore_elements = [];
		objStore_elements.push(createOrionElement('User', 'false', req.session.user, objStore_attributes));
		var objStore_body = createOrionBody(objStore_elements, 'UPDATE');

		request.post( {
			headers: HEADERS,
			url: URLS.orion_updateContext,
			body: JSON.stringify(objStore_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending update request to Orion: not logged out');
				res.sendStatus(500);
				return;
			}
			if(typeof JSON.parse(body).contextResponses !== 'undefined') {
				console.log(req.session.user + ' has logged out...');
				req.session.destroy();
				res.render('message', { title: '~ Tweet-A-Logout ~',
										stylesheet: 'message.css',
										author: AUTHORS,
										destination: '/',
										text: 'Logged out successfully.',
										button: 'Go back to Login Page' } );
			}
			else {
				console.log('Error in sending update request to Orion: not logged out');
				res.sendStatus(500);
				return;
			}
		} );
	}
} );

//API
app.post('/api/sendTweet', function(req, res) {
	console.log('Valid API, \"/api/sendTweet\", printing received json..');
	console.log(req.body);
	if(!checkSendTweetFields(req)) {
		res.json( { result: 'error',
					message: 'Missing -feeling-, -topic- and/or -tweet- in request body' } );
		console.log('Exit for missing field in sendTweet body');
		return;
	}
	//BEWARE
	//Text must not start with a single 'D' or 'M' + someone's screen name
	var feeling = req.body.feeling;
	var topic = req.body.topic;
	var accToken = req.dataSent.accToken;
	var accTokenS = req.dataSent.accTokenS;
	if(!checkHashTags(feeling, topic)) {
		res.json( { result: 'error',
					message: 'Wrong -feeling- and/or -topic- properties.' } );
		console.log('Exit because Feeling and/or Topic properties are wrong');
		return;
	}
	//no newline in tweet -> replacing with space
	var text_base = req.body.tweet.replace(/\r\n/g, " ");
	if(text_base > MAX_LENGTH) {
		res.json( { result: 'error',
					message: 'Message too long. Max length allowed: ' + MAX_LENGTH + ' characters.' } );
		console.log('Exit because Message too long.');
		return;
	}
	var text = text_base.concat(' #').concat(feeling).concat(' #').concat(topic);
	var text_enc = percentEncode(text);
	var tweet_baseUrl = URLS.tweet;
	var tweet_Url = tweet_baseUrl.concat('?status=').concat(text_enc);
	var tweet_nonce = genNonce();
	var tweet_timestamp = genTimestamp();
	var params = [];
	params.push(['oauth_token', accToken]);
	params.push(['status', text_enc]);
	var tweet_signature = genOauthSign('POST', tweet_baseUrl, tweet_nonce, tweet_timestamp, params, accTokenS);
	var tweet_authString = genAuthString(tweet_nonce, tweet_signature, tweet_timestamp, ['oauth_token', accToken]);
	var tweet_headers = {'Authorization': tweet_authString };

	request.post( {
		headers: tweet_headers,
		url: tweet_Url
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Twitter');
			res.json( { result: 'error',
						message: 'Couldn\'t send tweet to Twitter' } );
			return;
		}
		var resp = JSON.parse(body);
		if(typeof resp.errors !== 'undefined') {
			res.json( { result: 'error',
						message: 'Message not sent. There was an error with Twitter.' } );
			console.log(resp.errors);
			console.log('Exit because of an error returned by Twitter');
			return;
		}
		var mess_date = resp.created_at;
		var mess_author = resp.user.screen_name;
		var mess_id = resp.id_str;

		var objStore_attributes = [];
		// using html notation for forbidden characters in Orion
		var objStore_text = text_base.replace(/</g, "&lt").replace(/>/g, "&gt").replace(/"/g, "&quot").replace(/'/g, "&#39");
		objStore_text = objStore_text.replace(/=/g, "&#61").replace(/;/g, "&#59").replace(/\(/g, "&#40").replace(/\)/g, "&#41").replace(/\\/g, "&#92");
		objStore_attributes.push(createOrionAttribute('author', 'string', mess_author));
		objStore_attributes.push(createOrionAttribute('date', 'string', mess_date));
		objStore_attributes.push(createOrionAttribute('text', 'string', objStore_text));
		objStore_attributes.push(createOrionAttribute('feeling', 'string', feeling));
		objStore_attributes.push(createOrionAttribute('topic', 'string', topic));
		var objStore_elements = [];
		objStore_elements.push(createOrionElement('Message', 'false', mess_id, objStore_attributes));
		var objStore_body = createOrionBody(objStore_elements, 'APPEND');

		request.post( {
			headers: HEADERS,
			url: URLS.orion_updateContext,
			body: JSON.stringify(objStore_body)
		}, function(error, response, body) {
			if(!error)
				var objStore_bodyJson = JSON.parse(body);
			//if there's an Orion error, we delete tweet from Twitter!
			if(error || typeof objStore_bodyJson.contextResponses === 'undefined') {
				var destrTweet_url = URLS.destroy_tweet.concat(mess_id).concat('.json');
				var destrTweet_nonce = genNonce();
				var destrTweet_timestamp = genTimestamp();
				var params = [['oauth_token', accToken]];
				var destrTweet_signature = genOauthSign('POST', destrTweet_url, destrTweet_nonce, destrTweet_timestamp, params, accTokenS);
				var destrTweet_authString = genAuthString(destrTweet_nonce, destrTweet_signature, destrTweet_timestamp, ['oauth_token', accToken]);
				var destrTweet_headers = {'Authorization': destrTweet_authString };
				request.post( {
					headers: destrTweet_headers,
					url: destrTweet_url
				}, function(error, response, body) {
					if(!error)
						var destrTweet_resp = JSON.parse(body);
					if(!error && typeof destrTweet_resp.errors === 'undefined') {
						res.json( { result: 'error',
									message: 'Message not sent. There was an error with Object Store.' } );
						console.log('Exit because of an error returned by Object Store');
						return;
					}
					res.json( { result: 'error',
								message: 'Message `half` sent. It is on Twitter but was rejected by Object Store. Manually delete it on Twitter.' } );
					console.log('Exit because of an error returned by Object Store first, and later by Twitter on delete attempt.');
					return;
				} );
			}
			else {
				amqp.connect('amqp://rabbitmq', function(err, conn) {
					conn.createChannel(function(err, ch) {
						var key = feeling.concat('.').concat(topic);
						var message_life = 72 * 3600 * 1000; //72 hours (3 days) time to live
						ch.assertExchange(EXCHANGE, 'topic');
						ch.publish(EXCHANGE, key, new Buffer(mess_id), { persistent: true, expiration: message_life });
						console.log('# # # # # Message sent to exchange! # # # # #\nRouting key: %s\nMessage: %s', key, mess_id);
					} );
					setTimeout(function() {
						conn.close();
						var reply = 'Message id: '.concat(mess_id);
						res.json( { result: 'success',
									message: reply } );
					}, 1000);
				} );
			}
		} );
	} );
} );

app.delete('/api/delTweet', function(req, res) {
	console.log('Valid API, \"/api/delTweet\",  printing received json...');
	console.log(req.body);
	if(typeof req.body.id === 'undefined') {
		res.json( { result: 'error',
					message: 'Missing -id- field.' } );
		console.log('Exit because -id- field is missing');
		return;
	}
	var getTweetQuery_elements = [];
	getTweetQuery_elements.push(createOrionQueryElement('Message', 'false', req.body.id));
	var getTweetQuery_body = createOrionQueryBody(getTweetQuery_elements);

	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(getTweetQuery_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t search for tweet' } );
			return;
		}
		var queryForTweet = JSON.parse(body);
		if(typeof queryForTweet.contextResponses === 'undefined') { // 404 shouldn't be possible
			res.json( { result: 'error',
						message: 'There was an error with Object Store' } );
			console.log('Exit because of error with Object Store.');
			return;
		}
		else {
			var tweetFromQuery_attr = queryForTweet.contextResponses[0].contextElement.attributes;
			for(var i = 0; i < tweetFromQuery_attr.length; i++) {
				if(tweetFromQuery_attr[i].name === 'author') {
					if(tweetFromQuery_attr[i].value !== req.body.user) {
						res.json( { result: 'error',
									message: 'Could not delete message: you are not the author' } );
						console.log('Exit because attempted to delete another\'s message.');
						return;
					}
					break;
				}
			}
			var accToken = req.dataSent.accToken;
			var accTokenS = req.dataSent.accTokenS;
			var destrTweet_url = URLS.destroy_tweet.concat(req.body.id).concat('.json');
			var destrTweet_nonce = genNonce();
			var destrTweet_timestamp = genTimestamp();
			var params = [['oauth_token', accToken]];
			var destrTweet_signature = genOauthSign('POST', destrTweet_url, destrTweet_nonce, destrTweet_timestamp, params, accTokenS);
			var destrTweet_authString = genAuthString(destrTweet_nonce, destrTweet_signature, destrTweet_timestamp, ['oauth_token', accToken]);
			var destrTweet_headers = {'Authorization': destrTweet_authString };
			request.post( {
				headers: destrTweet_headers,
				url: destrTweet_url
			}, function(error, response, body) {
				if(error) {
					res.json( { result: 'error',
								message: 'Could not delete message: failed sending request to Twitter' } );
					console.log('Exit because could not send destroy request to Twitter.');
					return;
				}
				var destrTweet_resp = JSON.parse(body);
				if(typeof destrTweet_resp.errors !== 'undefined' && destrTweet_resp.errors[0].code !== 144) {
					res.json( { result: 'error',
								message: 'Could not delete message: Twitter returned an error' } );
					console.log('Exit because of an error returned by Twitter');
					return;
				}
				//Tweet destroyed or not found -> destroy in object store
				var objStore_elements = [];
				objStore_elements.push(createOrionElement('Message', 'false', req.body.id, []));
				var objStore_body = createOrionBody(objStore_elements, 'DELETE');

				request.post( {
					headers: HEADERS,
					url: URLS.orion_updateContext,
					body: JSON.stringify(objStore_body)
				}, function(error, response, body) {
					if(error) {
						res.json( { result: 'error',
									message: 'Could not delete message: failed sending request to Object Store' } );
						console.log('Exit because failed sending request to Orion. Message could have been deleted from Twitter nonetheless');
						return;
					}
					var queryResult = JSON.parse(body);
					if(typeof queryResult.errorCode !== 'undefined') { // 404, again, shouldn't be possible
						res.json( { result: 'error',
									message: 'Could not delete message: error returned by Object Store' } );
						console.log('Exit because of an error returned by Orion. Message could have been deleted from Twitter nonetheless');
						return;
					}
					res.json( { result: 'success',
								message: 'Tweet destroyed successfully.' } );
					console.log('Tweet destroyed.');
				} );
			} );
		}
	} );
} );

app.post('/api/getTweets', function(req, res) {
	console.log('Valid API, \"/api/getTweets\",  printing received json...');
	console.log(req.body);
	if(typeof req.body.feeling !== 'undefined' && !checkFeeling(req.body.feeling)) {
		res.json( { result: 'error',
					message: 'Wrong -feeling- property.' } );
		console.log('Exit because Feeling property is wrong');
		return;
	}
	if(typeof req.body.topic !== 'undefined' && !checkTopic(req.body.topic)) {
		res.json( { result: 'error',
					message: 'Wrong -topic- property.' } );
		console.log('Exit because Topic property is wrong');
		return;
	}
	if(typeof req.body.author !== 'undefined' && !checkUser(req.body.author)) {
		res.json( { result: 'error',
					message: 'Wrong -author- property.' } );
		console.log('Exit because Author property is wrong');
		return;
	}
	var getTweetsQuery_elements = [];
	getTweetsQuery_elements.push(createOrionQueryElement('Message', 'true', '.\*'));
	var getTweetsQuery_body = createOrionQueryBody(getTweetsQuery_elements); 

	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(getTweetsQuery_body),
		qs: { limit: 1000 }
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t retrieve tweets' } );
			return;
		}
		var queryForTweets = JSON.parse(body);
		if(typeof queryForTweets.errorCode !== 'undefined') {
			if(queryForTweets.errorCode.code === '404') {
				var respMessage = [];
				res.json( { result: 'success',
							message: respMessage } );
				console.log('Sent empty array, no user *ever* sent a message.');
				return;
			}
			else {
				res.json( { result: 'error',
							message: 'There was an error with Object Store' } );
				console.log('Exit because of error with Object Store.');
				return;
			}					
		}
		var tweetsFromQuery = queryForTweets.contextResponses;
		var all_tweets = [];
		var wantedTweets = [];
		var switch_value;
		if(typeof req.body.author !== 'undefined') {
			if(typeof req.body.feeling !== 'undefined') {
				if(typeof req.body.topic !== 'undefined') {
					switch_value = 0;
				}
				else {
					switch_value = 1;
				}
			}
			else {
				if(typeof req.body.topic !== 'undefined') {
					switch_value = 2;
				}
				else {
					switch_value = 3;
				}
			}
		}
		else {
			if(typeof req.body.feeling !== 'undefined') {
				if(typeof req.body.topic !== 'undefined') {
					switch_value = 4;
				}
				else {
					switch_value = 5;
				}
			}
			else {
				if(typeof req.body.topic !== 'undefined') {
					switch_value = 6;
				}
				else {
					switch_value = 7;
				}
			}
		}
		all_tweets = createTweetsList(tweetsFromQuery);

		switch (switch_value) {
			case 0:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.author === all_tweets[i].author && req.body.feeling === all_tweets[i].feeling
						&& req.body.topic === all_tweets[i].topic)
						wantedTweets.push(all_tweets[i]);
				}
				break;
			case 1:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.author === all_tweets[i].author && req.body.feeling === all_tweets[i].feeling)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 2:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.author === all_tweets[i].author && req.body.topic === all_tweets[i].topic)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 3:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.author === all_tweets[i].author)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 4:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.feeling === all_tweets[i].feeling && req.body.topic === all_tweets[i].topic)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 5:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.feeling === all_tweets[i].feeling)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 6:
				for(var i = 0; i < all_tweets.length; i++) {
					if(req.body.topic === all_tweets[i].topic)
						wantedTweets.push(all_tweets[i]);							
				}						
				break;
			case 7:
				wantedTweets = all_tweets;
				break;
		}
		var result = {
			result: 'success',
			message: wantedTweets.reverse()
		};
		res.json(result);
	} );
} );

app.post('/api/getUsers', function(req, res) {
	console.log('Valid API, \"/api/getUsers\", printing received json...');
	console.log(req.body);
	var usersQuery_elements = [];
	usersQuery_elements.push(createOrionQueryElement('User', 'true', '.\*'));
	usersQuery_body = createOrionQueryBody(usersQuery_elements);
			
	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(usersQuery_body),
		qs: { limit: 1000 }
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t retrieve users' } );
			return;
		}
		var queryRes = JSON.parse(body);
		if(typeof queryRes.contextResponses === 'undefined') {
			//It could not be 'errorCode 404', because if we're here we are registered,
			//and that code signifies NO user registered.
			res.json( { result: 'error',
						message: 'Could not retrieve userlist.' } );
			console.log('Exit because couldn\'t retrieve userlist');
			return;
		}
		var userlist = [];
		var contextRes = queryRes.contextResponses;
		for(var i = 0; i < contextRes.length; i++)
			userlist.push(contextRes[i].contextElement.id);
		res.json( { result: 'success',
					message: userlist } );
		console.log('Sent userlist.');
	} );
} );

app.post('/api/getDataset', function(req, res) {
	console.log('Valid API, \"/api/getDataset\",  printing received json...');
	console.log(req.body);
	if(typeof req.body.feeling !== 'undefined' && !checkFeeling(req.body.feeling)) {
		res.json( { result: 'error',
					message: 'Wrong -feeling- property.' } );
		console.log('Exit because Feeling property is wrong');
		return;
	}
	if(typeof req.body.topic !== 'undefined' && !checkTopic(req.body.topic)) {
		res.json( { result: 'error',
					message: 'Wrong -topic- property.' } );
		console.log('Exit because Topic property is wrong');
		return;
	}
	if(typeof req.body.author !== 'undefined' && !checkUser(req.body.author)) {
		res.json( { result: 'error',
					message: 'Wrong -author- property.' } );
		console.log('Exit because Author property is wrong');
		return;
	}
	var userSent = req.body.user;
	var codeSent = req.body.apiCode;
	var text = [];
	var getTweets_url = URLS.api.concat('/getTweets');
	var getTweets_body = { 
		apiCode: codeSent,
		user: userSent
	};
	if(typeof req.body.author !== 'undefined')
		getTweets_body['author'] = req.body.author;
	if(typeof req.body.feeling !== 'undefined')
		getTweets_body['feeling'] = req.body.feeling;
	if(typeof req.body.topic !== 'undefined')
		getTweets_body['topic'] = req.body.topic;

	request.post( {
		url: getTweets_url,
		headers: HEADERS,
		body: JSON.stringify(getTweets_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to retrieve data');
			res.json( { result: 'error',
						message: 'Couldn\'t send request to retrieve data' } );
			return;
		}
		var body_j = JSON.parse(body);
		if(body_j.result === 'error') {
			console.log('There was an error retrieving data');
			res.json( { result: 'error',
						message: 'Couldn\'t retrieve data' } );
			return;
		}
		var tweets = body_j.message;
		for(var i = 0; i < tweets.length; i++)
			text.push(tweets[i].text);
		
		var dataset = genDataset(text);
		res.json( { result: 'success',
					message: dataset } );
		console.log('Sent dataset.');
	} );
} );

app.post('/api/getChart', function(req, res) {
	console.log('Valid API, \"/api/getChart\",  printing received json...');
	console.log(req.body);
	if(!checkGetChartFields(req)) {
		res.json( { result: 'error',
					message: 'Missing -chart- and/or -scope- field in request body' } );
		console.log('Exit for missing \"chart\" and/or \"scope\" field in request body');
		return;
	}
	var userSent = req.body.user;
	var codeSent = req.body.apiCode;
	var chartSent = req.body.chart;
	var scopeSent = req.body.scope;
	if(!checkChart(chartSent)) {
		res.json( { result: 'error',
					message: 'Wrong -chart- property.' } );
		console.log('Exit because Chart property is wrong');
		return;
	}
	if(chartSent.slice(0, 3) === 'Pie') {
		sendPie(scopeSent, res, userSent, codeSent, chartSent);
		return;
	}
	if(chartSent.slice(0, 3) === 'Bar') {
		sendBar(scopeSent, res, userSent, codeSent, chartSent);
		return;
	}
} );

var sendPie = function(scope, res, user, code, chart) {
	if(!checkUser(scope) && scope !== '%%') {
		res.json( { result: 'error',
					message: 'Wrong -scope- property.' } );
		console.log('Exit because Scope property is wrong');
		return;
	}
	var chart_url = URLS.charts;
	var chart_type = 'cht=p';
	var chart_size = 'chs=500x350';
	var chart_color;
	var pie_type = chart.slice(4);
	var chart_labels = 'chl=';
	var chart_title;
	var chart_data = 'chd=t:';
	var chart_scaling = 'chds=a';
	var chart_legend = 'chdl=';
	if(pie_type === 'Feelings' || checkTopic(pie_type)) {
		var numFeeling = new Array(FEELINGS.length);
		for(var i = 0; i < FEELINGS.length; i++) {
			numFeeling[i] = 0;
			chart_labels = chart_labels.concat(FEELINGS[i]).concat('|');
		}
		chart_color = 'chco=0000FF'; //blue gradient
		chart_labels = chart_labels.slice(0, chart_labels.length - 1);
		if(pie_type === 'Feelings')
			chart_title = 'chtt=Feelings';
		else
			chart_title = 'chtt='.concat(pie_type).concat('`s+Feelings');
	}
	if(pie_type === 'Topics' || checkFeeling(pie_type)) {
		var numTopic = new Array(TOPICS.length);
		for(var i = 0; i < TOPICS.length; i++) {
			numTopic[i] = 0;
			chart_labels = chart_labels.concat(TOPICS[i]).concat('|');
		}
		chart_color = 'chco=00BC00'; //green gradient
		chart_labels = chart_labels.slice(0, chart_labels.length - 1);
		if(pie_type === 'Topics')
			chart_title = 'chtt=Topics';
		else
			chart_title = 'chtt='.concat(pie_type).concat('`s+Topics');
	}
	var tw_url = URLS.api.concat('/getTweets');
	var tw_body = {
		apiCode: code,
		user: user
	};
	if(checkUser(scope))
		tw_body['author'] = scope
	if(checkTopic(pie_type))
		tw_body['topic'] = pie_type;
	if(checkFeeling(pie_type))
		tw_body['feeling'] = pie_type;
	
	request.post( {
		url: tw_url,
		headers: HEADERS,
		body: JSON.stringify(tw_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to retrieve data');
			res.json( { result: 'error',
						message: 'Couldn\'t send request to retrieve data' } );
			return;
		}
		var body_json = JSON.parse(body);
		if(body_json.result === 'error') {
			res.json( { result: 'error',
						message: 'Could not retrieve data.' } );
			console.log('Exit because couldn\'t retrieve data');
			return;
		}
		var all_tweets = body_json.message;
		if(all_tweets.length === 0) {
			res.json( { result: 'success',
						message: '' } );
			console.log('Success, sent empty string');
		 	return;
		}
		if(pie_type === 'Feelings' || checkTopic(pie_type)) {
			for(var i = 0; i < all_tweets.length; i++) {
				for(var j = 0; j < FEELINGS.length; j++) {
					if(all_tweets[i].feeling === FEELINGS[j])
						numFeeling[j]++;
				}
			}for(var i = 0; i < FEELINGS.length; i++) {
				chart_data = chart_data.concat(numFeeling[i]).concat(',');
				chart_legend = chart_legend.concat(FEELINGS[i] + '+=+' + numFeeling[i]).concat('|');
			}
			chart_data = chart_data.slice(0, chart_data.length - 1);
			chart_legend = chart_legend.slice(0, chart_legend.length - 1);
		}
		if(pie_type === 'Topics' || checkFeeling(pie_type)) {
			for(var i = 0; i < all_tweets.length; i++) {
				for(var j = 0; j < FEELINGS.length; j++) {
					if(all_tweets[i].topic === TOPICS[j])
						numTopic[j]++;
				}
			}
			for(var i = 0; i < TOPICS.length; i++) {
				chart_data = chart_data.concat(numTopic[i]).concat(',')
				chart_legend = chart_legend.concat(TOPICS[i] + '+=+' + numTopic[i]).concat('|');
			}
			chart_data = chart_data.slice(0, chart_data.length - 1);
			chart_legend = chart_legend.slice(0, chart_legend.length - 1);
		}
		if(scope === '%%')
			chart_title = chart_title.concat('|All+Users');
		else
			chart_title = chart_title.concat('|').concat(scope);
		chart_url = chart_url.concat('?').concat(chart_type).concat('&').concat(chart_size).concat('&').concat(chart_color).concat('&');
		chart_url = chart_url.concat(chart_labels).concat('&').concat(chart_data).concat('&').concat(chart_scaling).concat('&');
		chart_url = chart_url.concat(chart_title);
		chart_url = chart_url.concat('&').concat(chart_legend);
		res.json( { result: 'success',
					message: chart_url } );
		console.log('Sent url for chart');
	} );
};

var sendBar = function(scope, res, user, code, chart) {
	if(!checkUser(scope) && scope !== '%%' && !checkCompareScope(scope)) {
		res.json( { result: 'error',
					message: 'Wrong -scope- property.' } );
		console.log('Exit because Scope property is wrong');
		return;
	}
	var chart_url = URLS.charts;
	var chart_type = 'cht=bvg';
	var chart_size;
	var chart_labType = 'chxt=x,y';
	var chart_labels = 'chxl=0:'
	var chart_title;
	var chart_space = 'chbh=15,6,10';
	var bar_type;
	var chart_legend = 'chdl=';
	var chart_color;
	if(chart === 'Bar')
		chart_title = 'chtt=Most+Used+Words';
	else {
		bar_type = chart.slice(4);
		chart_title = 'chtt='.concat(bar_type).concat('`s+Most+Used+Words');
	}
	var chart_data = 'chd=t:';
	var chart_scaling = 'chds=a';
	var tw_url = URLS.api.concat('/getDataset');
	if(checkUser(scope) || scope === '%%') {
		chart_size = 'chs=750x400';
		chart_color = 'chco=4D89F9';
		var tw_body = {
			apiCode: code,
			user: user
		};
		if(checkUser(scope))
			tw_body['author'] = scope;
		if(checkTopic(bar_type))
			tw_body['topic'] = bar_type;
		if(checkFeeling(bar_type))
			tw_body['feeling'] = bar_type;
		
		request.post( {
			url: tw_url,
			headers: HEADERS,
			body: JSON.stringify(tw_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending request to retrieve data');
				res.json( { result: 'error',
							message: 'Couldn\'t send request to retrieve data' } );
				return;
			}
			var body_json = JSON.parse(body);
			if(body_json.result === 'error') {
				res.json( { result: 'error',
							message: 'Could not retrieve data.' } );
				console.log('Exit because couldn\'t retrieve data');
				return;
			}
			var dataset = body_json.message;
			var dataset_arr = [];
			for(var key in dataset)
				dataset_arr.push([key, dataset[key]]); // {'k': 'v'} -> ['k', 'v']
			dataset_arr.sort(function(a, b) {
				return b[1] - a[1];
			} );
			if(dataset_arr.length === 0) {
				res.json( { result: 'success',
							message: '' } );
				console.log('Success, sent empty string.');
			 	return;
			}
			dataset_arr = dataset_arr.slice(0, 20);

			for(var i = 0; i < dataset_arr.length; i++) {
				chart_data = chart_data.concat(dataset_arr[i][1].toString()).concat(',');
				chart_labels = chart_labels.concat('|').concat('\(' + (i + 1).toString() + '\)');
				chart_legend = chart_legend.concat('\(' + (i + 1).toString() + '\)+=+').concat(dataset_arr[i][0]).concat('|');
			}
			chart_data = chart_data.slice(0, chart_data.length - 1);
			chart_legend = chart_legend.slice(0, chart_legend.length - 1);
			if(scope === '%%')
				chart_title = chart_title.concat('|All+Users');
			else
				chart_title = chart_title.concat('|').concat(scope);
			chart_url = chart_url.concat('?').concat(chart_type).concat('&').concat(chart_size).concat('&').concat(chart_color).concat('&');
			chart_url = chart_url.concat(chart_labels).concat('&').concat(chart_data).concat('&').concat(chart_scaling).concat('&');
			chart_url = chart_url.concat(chart_title).concat('&').concat(chart_labType).concat('&').concat(chart_space).concat('&').concat(chart_legend);
			res.json( { result: 'success',
						message: chart_url } );
			console.log('Sent url for chart');
		} );
	}
	else {
		chart_size = 'chs=1000x300';
		var chart_legPos = 'chdlp=b';
		chart_color = 'chco=4D89F9,00CC00';
		var scope_arr = scope.split('%');
		console.log(scope_arr);
		chart_title = chart_title.concat('|').concat(scope_arr[0]).concat('+vs.+').concat(scope_arr[1]);
		var tw_body0 = {
			apiCode: code,
			user: user,
			author: scope_arr[0]
		};
		if(checkTopic(bar_type))
			tw_body0['topic'] = bar_type;
		if(checkFeeling(bar_type))
			tw_body0['feeling'] = bar_type;

		request.post( {
			url: tw_url,
			headers: HEADERS,
			body: JSON.stringify(tw_body0)
		}, function(error, response, body0) {
			if(error) {
				console.log('Error in sending request to retrieve data');
				res.json( { result: 'error',
							message: 'Couldn\'t send request to retrieve data' } );
				return;
			}
			var body_json0 = JSON.parse(body0);
			if(body_json0.result === 'error') {
				res.json( { result: 'error',
							message: 'Could not retrieve data.' } );
				console.log('Exit because couldn\'t retrieve data');
				return;
			}
			var tw_body1 = {
				apiCode: code,
				user: user,
				author: scope_arr[1]
			};
			if(checkTopic(bar_type))
				tw_body1['topic'] = bar_type;
			if(checkFeeling(bar_type))
				tw_body1['feeling'] = bar_type;

			request.post( {
				url: tw_url,
				headers: HEADERS,
				body: JSON.stringify(tw_body1)
			}, function(error, response, body1) {
				if(error) {
					console.log('Error in sending request to retrieve data');
					res.json( { result: 'error',
								message: 'Couldn\'t send request to retrieve data' } );
					return;
				}
				var body_json1 = JSON.parse(body1);
				if(body_json1.result === 'error') {
					res.json( { result: 'error',
								message: 'Could not retrieve data.' } );
					console.log('Exit because couldn\'t retrieve data');
					return;
				}
				var dataset0 = body_json0.message;
				var dataset_arr0 = [];
				for(var key in dataset0)
					dataset_arr0.push([key, dataset0[key]]); // {'k': 'v'} -> ['k', 'v']
					dataset_arr0.sort(function(a, b) {
					return b[1] - a[1];
				} );
				if(dataset_arr0.length === 0) {
					res.json( { result: 'success',
								message: '' } );
					console.log('Success, sent empty string.');
					return;
				}
				var dataset1 = body_json1.message;
				var dataset_arr1 = [];
				for(var key in dataset1)
					dataset_arr1.push([key, dataset1[key]]); // {'k': 'v'} -> ['k', 'v']
					dataset_arr1.sort(function(a, b) {
					return b[1] - a[1];
				} );
				if(dataset_arr1.length === 0) {
					res.json( { result: 'success',
								message: '' } );
					console.log('Success, sent empty string.');
					return;
				}
				var dataset_arr = [];
				for(var i = 0; i < dataset_arr0.length; i++) {
					for(var j = 0; j < dataset_arr1.length; j++) {
						if(dataset_arr0[i][0] === dataset_arr1[j][0]) {
							var elem = [dataset_arr0[i], dataset_arr1[j]];
							console.log('--- Found Element ---');	//array elems' indexes [ [['k0','v0'],['k1','v1']], [[],[]], ... ]
							dataset_arr.push(elem); 			// -> [ [[000,001],[010,011]], ... ,[[i00,i01],[i10,i11]], ... ]
						}										//			   ^
					}											//			   | elem of index [0][0][1]
				}
				console.log('--- DATASET ARR ---');
				console.log(dataset_arr);

				if(dataset_arr.length === 0) {
					res.json( { result: 'success',
								message: '' } );
					console.log('Success, sent empty string.');
					return;
				}
				dataset_arr = dataset_arr.slice(0, 20); //randomizziamo?
				var data0 = '',
					data1 = '',
					legend0 = scope_arr[0],
					legend1 = scope_arr[1];
				for(var i = 0; i < dataset_arr.length; i++) {
					data0 = data0.concat(dataset_arr[i][0][1].toString()).concat(',');
					data1 = data1.concat(dataset_arr[i][1][1].toString()).concat(',');
					chart_labels = chart_labels.concat('|').concat(dataset_arr[i][0][0]);
				}
				data0 = data0.slice(0, data0.length - 1);
				data1 = data1.slice(0, data1.length - 1);
				chart_data = chart_data.concat(data0).concat('|').concat(data1);
				chart_legend = chart_legend.concat(legend0).concat('|').concat(legend1);
				chart_url = chart_url.concat('?').concat(chart_type).concat('&').concat(chart_size).concat('&').concat(chart_color).concat('&');
				chart_url = chart_url.concat(chart_labels).concat('&').concat(chart_data).concat('&').concat(chart_scaling).concat('&').concat(chart_space).concat('&');
				chart_url = chart_url.concat(chart_title).concat('&').concat(chart_labType).concat('&').concat(chart_legend).concat('&').concat(chart_legPos);

				res.json( { result: 'success',
							message: chart_url } );	
				console.log('Sending url for chart');
			} );
		} );
	}
};

app.delete('/api/setNotifications', function(req, res) {
	console.log('Valid API, \"/api/setNotifications\" (DELETE),  printing received json...');
	console.log(req.body);
	if(!checkSetNotif(req.body)) {
		res.json( { result: 'error',
					message: 'Missing field(s) in request body. All as it was before.' } );
		console.log('Exit for missing field(s) in request body');
		return;
	}
	if(!Array.isArray(req.body.feelings) && !Array.isArray(req.body.topics)) {
		res.json( { result: 'error',
					message: '-feelings- and -topics- MUST be arrays.' } );
		console.log('Exit for \"feelings\" and/or \"topics\" not array.');
		return;
	}
	if(typeof req.body.feelings !== 'undefined') {
		if(!req.body.feelings.every(checkFeeling)) {
			res.json( { result: 'error',
						message: 'One or more -feelings- are wrong.' } );
			console.log('Exit for wrong feeling(s) in request body');
			return;
		}
		if(req.body.feelings.length === 0) {
			res.json( { result: 'error',
						message: 'No -feelings- notifications to unset' } );
			console.log('No feelings notifications to unset!');
			return;
		}
	}
	if(typeof req.body.topics !== 'undefined') {
		if(!req.body.topics.every(checkTopic)) {
			res.json( { result: 'error',
						message: 'One or more -topics- are wrong.' } );
			console.log('Exit for wrong topic(s) in request body');
			return;
		}
		if(req.body.topics.length === 0) {
			res.json( { result: 'error',
						message: 'No -topics- notifications to unset' } );
			console.log('No topics notifications to unset!');
			return;
		}
	}
	var queryUser_elements = [];
	queryUser_elements.push(createOrionQueryElement('User', 'false', req.body.user));
	queryUser_body = createOrionQueryBody(queryUser_elements);
	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(queryUser_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t send request to Object Store' } );
			return;
		}
		var queryRes = JSON.parse(body);
		//errorCode 404 NOT possible
		if(typeof queryRes.contextResponses === 'undefined') {
			res.json( { result: 'error',
						message: 'Could not retrieve data' } );
			console.log('Exit because Couldn\'t retrieve data.');
			return;
		}
		var contextRes = queryRes.contextResponses;
		var contextRes_attr = contextRes[0].contextElement.attributes;
		var notif_toUpdate;
		for(var i = 0; i < contextRes_attr.length; i++) {
			if(contextRes_attr[i].name === 'notif_wanted') {
				notif_toUpdate = contextRes_attr[i].value;
				break;
			}
		}
		if(emptyObject(notif_toUpdate.feelings) && emptyObject(notif_toUpdate.topics)) {
			res.json( { result: 'success',
						message: notif_toUpdate } );
			console.log('No notifications to unset!');
			return;
		}
		if(typeof req.body.feelings !== 'undefined') {
			if(!emptyObject(notif_toUpdate.feelings)) {
				for(var i = 0; i < req.body.feelings.length; i++) {
					for(var j = 0; j < notif_toUpdate.feelings.length; j++) {
						if(req.body.feelings[i] === notif_toUpdate.feelings[j]) {
							notif_toUpdate.feelings.splice(j, 1);
						}
					}
				}
			}
		}
		if(typeof req.body.topics !== 'undefined') {
			if(!emptyObject(notif_toUpdate.topics)) {
				for(var i = 0; i < req.body.topics.length; i++) {
					for(var j = 0; j < notif_toUpdate.topics.length; j++) {
						if(req.body.topics[i] === notif_toUpdate.topics[j]) {
							notif_toUpdate.topics.splice(j, 1);
						}
					}
				}
			}
		}
		var update_attribute = [];
		update_attribute.push(createOrionAttribute('notif_wanted', 'object', notif_toUpdate));
		var update_elements = [];
		update_elements.push(createOrionElement('User', 'false', req.body.user, update_attribute));
		var update_body = createOrionBody(update_elements, 'UPDATE');

		request.post( {
			headers: HEADERS,
			url: URLS.orion_updateContext,
			body: JSON.stringify(update_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending request to Orion');
				res.json( { result: 'error',
							message: 'Couldn\'t update Object Store' } );
				return;
			}
			var body_j = JSON.parse(body);
			if(body_j.contextResponses === 'undefined') {
				res.json( { result: 'error',
							message: 'Error in updating notification settings' } );
				console.log('Error in updating user notification settings');
				return;
			}

			amqp.connect('amqp://rabbitmq', function(err, conn) {
				conn.createChannel(function(err, ch) {			
					ch.assertExchange(EXCHANGE, 'topic');
					var queue = req.body.user.concat('_queue');
					ch.assertQueue(queue);					
					//unsetting only new 'un'-bindings
					if(typeof req.body.feelings !== 'undefined') {
						req.body.feelings.forEach(function(key) {
							ch.unbindQueue(queue, EXCHANGE, key.concat('.').concat('*'));
						} );
					}
					if(typeof req.body.topics !== 'undefined') {
						req.body.topics.forEach(function(key) {
							ch.unbindQueue(queue, EXCHANGE, '*.'.concat(key));
						} );
					}
				} );
				setTimeout(function() {
					conn.close();
					res.json( { result: 'success',
								message: notif_toUpdate } );
					console.log('Notifications settings unset!');
				}, 1000);
			} );
		} );
	} );
} );

app.post('/api/setNotifications', function(req, res) {
	console.log('Valid API, \"/api/setNotifications\" (POST),  printing received json...');
	console.log(req.body);
	if(!checkSetNotif(req.body)) {
		res.json( { result: 'error',
					message: 'Missing field(s) in request body. All as it was before.' } );
		console.log('Exit for missing field(s) in request body');
		return;
	}
	if(!Array.isArray(req.body.feelings) && !Array.isArray(req.body.topics)) {
		res.json( { result: 'error',
					message: '-feelings- and -topics- MUST be arrays.' } );
		console.log('Exit for \"feelings\" and/or \"topics\" not array.');
		return;
	}
	if(typeof req.body.feelings !== 'undefined') {
		if(!req.body.feelings.every(checkFeeling)) {
			res.json( { result: 'error',
						message: 'One or more -feelings- are wrong.' } );
			console.log('Exit for wrong feeling(s) in request body');
			return;
		}
		if(req.body.feelings.length === 0) {
			res.json( { result: 'error',
						message: 'No -feelings- notifications to set' } );
			console.log('No feelings notifications to set!');
			return;
		}
	}
	if(typeof req.body.topics !== 'undefined') {
		if(!req.body.topics.every(checkTopic)) {
			res.json( { result: 'error',
						message: 'One or more -topics- are wrong.' } );
			console.log('Exit for wrong topic(s) in request body');
			return;
		}
		if(req.body.topics.length === 0) {
			res.json( { result: 'error',
						message: 'No -topics- notifications to set' } );
			console.log('No topics notifications to set!');
			return;
		}
	}
	var queryUser_elements = [];
	queryUser_elements.push(createOrionQueryElement('User', 'false', req.body.user));
	queryUser_body = createOrionQueryBody(queryUser_elements);
	request.post( {
		headers: HEADERS,
		url: URLS.orion_queryContext,
		body: JSON.stringify(queryUser_body)
	}, function(error, response, body) {
		if(error) {
			console.log('Error in sending request to Orion');
			res.json( { result: 'error',
						message: 'Couldn\'t send request to Object Store' } );
			return;
		}
		var queryRes = JSON.parse(body);
		//errorCode 404 NOT possible
		if(typeof queryRes.contextResponses === 'undefined') {
			res.json( { result: 'error',
						message: 'Could not retrieve data' } );
			console.log('Exit because Couldn\'t retrieve data.');
			return;
		}
		var contextRes = queryRes.contextResponses;
		var contextRes_attr = contextRes[0].contextElement.attributes;
		var notif_toUpdate;
		for(var i = 0; i < contextRes_attr.length; i++) {
			if(contextRes_attr[i].name === 'notif_wanted') {
				notif_toUpdate = contextRes_attr[i].value;
				break;
			}
		}
		if(typeof notif_toUpdate.feelings === 'string' && notif_toUpdate.feelings.length === 0)
			notif_toUpdate.feelings = [];
		if(typeof notif_toUpdate.topics === 'string' && notif_toUpdate.topics.length === 0)
			notif_toUpdate.topics = [];

		if(typeof req.body.feelings !== 'undefined') {
			if(emptyObject(notif_toUpdate.feelings))
				notif_toUpdate.feelings = req.body.feelings;
			else {
				for(var i = 0; i < req.body.feelings.length; i++) {
					if(!notif_toUpdate.feelings.some(checkInArray, req.body.feelings[i]))
						notif_toUpdate.feelings.push(req.body.feelings[i])
				}
			}
		}

		if(typeof req.body.topics !== 'undefined') {
			if(emptyObject(notif_toUpdate.topics))
				notif_toUpdate.topics = req.body.topics;
			else {
				for(var i = 0; i < req.body.topics.length; i++) {
					if(!notif_toUpdate.topics.some(checkInArray, req.body.topics[i]))
						notif_toUpdate.topics.push(req.body.topics[i])
				}
			}
		}
		var update_attribute = [];
		update_attribute.push(createOrionAttribute('notif_wanted', 'object', notif_toUpdate));
		var update_elements = [];
		update_elements.push(createOrionElement('User', 'false', req.body.user, update_attribute));
		var update_body = createOrionBody(update_elements, 'UPDATE');

		request.post( {
			headers: HEADERS,
			url: URLS.orion_updateContext,
			body: JSON.stringify(update_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending request to Orion');
				res.json( { result: 'error',
							message: 'Couldn\'t update Object Store' } );
				return;
			}
			var body_j = JSON.parse(body);
			if(body_j.contextResponses === 'undefined') {
				res.json( { result: 'error',
							message: 'Error in updating notification settings' } );
				console.log('Error in updating user notification settings');
				return;
			}

			amqp.connect('amqp://rabbitmq', function(err, conn) {
				conn.createChannel(function(err, ch) {			
					ch.assertExchange(EXCHANGE, 'topic');
					var queue = req.body.user.concat('_queue');
					ch.assertQueue(queue);
					
					//setting only new bindings, no all bindings (notif_toUpdate contains new AND old)
					if(typeof req.body.feelings !== 'undefined') {
						req.body.feelings.forEach(function(key) {
							ch.bindQueue(queue, EXCHANGE, key.concat('.').concat('*'));
						} );
					}
					if(typeof req.body.topics !== 'undefined') {
						req.body.topics.forEach(function(key) {
							ch.bindQueue(queue, EXCHANGE, '*.'.concat(key));
						} );
					}
				} );
				setTimeout(function() {
					conn.close();
					res.json( { result: 'success',
								message: notif_toUpdate } );
					console.log('Notifications settings set!');
				}, 1000);
			} );
		} );
	} );
} );

app.post('/api/getNotifications', function(req, res) {
	console.log('Valid API, \"/api/getNotifications\",  printing received json...');
	console.log(req.body);
	var notifications= [];
	amqp.connect('amqp://rabbitmq', function(err, conn) {
		conn.createChannel(function(err, ch) {
			ch.assertExchange(EXCHANGE, 'topic');
			var queue = req.body.user.concat('_queue');
			ch.assertQueue(queue);
			ch.consume(queue, function(msg) {
				notifications.push(msg.content.toString());
				ch.ack(msg); //ch.ackAll() doesn't seem to work
			}, { noAck: false } );
		} );
		setTimeout(function() {
			conn.close();
			if(notifications.length === 0) {
				res.json( { result: 'success',
							message: notifications } );
				console.log('Notifications (empty array) sent!');
				return;	
			}
			var queryMess_elements = [];
			for(var i = 0; i < notifications.length; i++) {
				queryMess_elements.push(createOrionQueryElement('Message', 'false', notifications[i]));
			}
			var queryMess_body = createOrionQueryBody(queryMess_elements);
	
			request.post( {
				headers: HEADERS,
				url: URLS.orion_queryContext,
				body: JSON.stringify(queryMess_body)
			}, function(error, response, body) {
				if(error) {
					console.log('Error in sending request to Orion');
					res.json( { result: 'error',
								message: 'Couldn\'t send request to Object Store' } );
					return;
				}
				var body_j = JSON.parse(body);
				//errorCode 404 shouldn't be possible, if I have mess_id it should exist in orion
				if(typeof body_j.contextResponses === 'undefined') {
					if(body_j.errorCode.code === '404') {
						res.json( { result: 'success',
									message: [] } );
						console.log('Notifications (empty array) sent!');
						return;
					}
					res.json( { result: 'error',
								message: 'Error in retrieving ' } );
					console.log('Error in retrieving notifications');
					return;
				}
				var tweetsFromQuery = body_j.contextResponses;
				var wanted = createTweetsList(tweetsFromQuery);
				console.log(wanted);
				res.json( { result: 'success',
							message: wanted } );
				console.log('Notifications sent!');
			} );
		}, 2000);
	} );
} );

// Returns 404 page for non-existant resources
app.use(function(req, res, next) {
	// http://expressjs.com/it/starter/faq.html#in-che-modo--possibile-gestire-le-risposte-404
	res.status(404).render('404', { title: 'Oh no, not again...',
									stylesheet: '40x.css',
									author: AUTHORS });
} );

var server;

//Reset attributes of users in object store at startup
var initQuery_elements = [];
initQuery_elements.push(createOrionQueryElement('User', 'true', '.\*'));
var initQuery_body = createOrionQueryBody(initQuery_elements);

request.post( {
	headers: HEADERS,
	url: URLS.orion_queryContext,
	body: JSON.stringify(initQuery_body),
	qs: { limit: 1000 }
}, function(error, response, body) {
	if(error) {
		console.log('Error in sending query request to Orion');
		process.exit(0);
	}
	var queryRes = JSON.parse(body);
	if(typeof queryRes.contextResponses === 'undefined') {
		if (queryRes.errorCode.code === '404') {
			console.log('***** First launch of \"Tweet-A-Feeling\"! (or no users ever used it) *****');
			server = app.listen(4242, function() {
				var port = server.address().port;
				console.log('***** \"Tweet-A-Feeling\" server listening on port %s *****', port);
			} );
			return;
		}
		else {
			console.log('Error in querying Orion, couldn\'t retrieve users');
			process.exit(0);
		}
	}
	var contextRes = queryRes.contextResponses;
	for(var i = 0; i < contextRes.length; i++) {
		var reset_user = contextRes[i].contextElement.id;
		var reset_attributes = [];
		reset_attributes.push(createOrionAttribute('logged', 'boolean', 'false'));
		reset_attributes.push(createOrionAttribute('Access_Token', 'string', ''));
		reset_attributes.push(createOrionAttribute('Access_Token_S', 'string', ''));
		var reset_elements = [];
		reset_elements.push(createOrionElement('User', 'false', reset_user, reset_attributes));
		var reset_body = createOrionBody(reset_elements, 'APPEND');

		request.post( {
			headers: HEADERS,
			url: URLS.orion_updateContext,
			body: JSON.stringify(reset_body)
		}, function(error, response, body) {
			if(error) {
				console.log('Error in sending update request to Orion');
				process.exit(0);
			}
			var body_j = JSON.parse(body);
			if(body_j.contextResponses === 'undefined') {
				console.log('Error in resetting a user, exiting...');
				process.exit(0);
			}
			var resetted = body_j.contextResponses[0].contextElement.id;
			console.log('Resetted user %s', resetted);
			USERS.push(resetted);
		} );
	}
	console.log('***** Timeout before listening: 5 sec *****');
	setTimeout(function() {
		console.log(USERS);
		server = app.listen(4242, function() {
			var port = server.address().port;
			console.log('***** \"Tweet-A-Feeling\" server listening on port %s *****', port);
		} );
	}, 5000 );
} );
