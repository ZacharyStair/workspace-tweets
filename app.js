import express from 'express';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import zipcode from 'zipcode';
import request from "request";
import Twitter from 'twitter';
import uuidv4 from 'uuid/v4';
import oauthSignature from 'oauth-signature';
import encodeUrl from 'encodeurl';
import qs from 'querystring';

// Watson Work Services URL
const watsonWork = "https://api.watsonwork.ibm.com";
const WWS_GRAPHQL_URL = `${watsonWork}/graphql`;

// Application Id, obtained from registering the application at https://developer.watsonwork.ibm.com
const appId = process.env.TWITTER_CLIENT_ID;

// Application secret. Obtained from registration of application.
const appSecret = process.env.TWITTER_CLIENT_SECRET;

// Webhook secret. Obtained from registration of a webhook.
const webhookSecret = process.env.TWITTER_WEBHOOK_SECRET;

// Twitter API keys obtained via: https://apps.twitter.com (see README for more info)
// a JSON object with all the authentication info for Twitter


// Keyword to "listen" for when receiving outbound webhook calls.
const webhookKeyword = "@twitter";

const failMessage =
`Hey, maybe it's me... maybe it's Twitter, but I sense the fail whale should be here... Try again later`;

const successMessage = (username, tweetText, tweetId) => {
  return `*Tweet* from [@${username}](http://twitter.com/${username}): ${tweetText}. Click [here](https://twitter.com/${username}/status/${tweetId}) to view more. \r\n\r\n`;
};

const app = express();

// Send 200 and empty body for requests that won't be processed.
const ignoreMessage = (res) => {
  res.status(200).end();
}

// Process webhook verification requests
const verifyCallback = (req, res) => {
  console.log("Verifying challenge");

  const bodyToSend = {
    response: req.body.challenge
  };

  // Create a HMAC-SHA256 hash of the recieved body, using the webhook secret
  // as the key, to confirm webhook endpoint.
  const hashToSend =
    crypto.createHmac('sha256', webhookSecret)
    .update(JSON.stringify(bodyToSend))
    .digest('hex');

  res.set('X-OUTBOUND-TOKEN', hashToSend);
  res.send(bodyToSend).end();
};

// Validate events coming through and process only message-created or verification events.
const validateEvent = (req, res, next) => {

  // Event to Event Handler mapping
  const processEvent = {
    'verification': verifyCallback,
    'message-created': () => next(),
    'message-annotation-added': () => next()
  };

  console.log(req.body.type);

  // If event exists in processEvent, execute handler. If not, ignore message.
  return (processEvent[req.body.type]) ?
    processEvent[req.body.type](req, res) : ignoreMessage(res);
};

// Authenticate Twitter
const authenticateTwitter = (req, callback) => {
  console.log('we are trying to authenticate with twitter and here is out req:');

  const httpMethod = 'POST';
  const requestTokenUrl = 'https://api.twitter.com/oauth/request_token';
  const callbackUrl = process.env.CALLBACK_URL + '/authsuccess';
  const encodedCallbackUrl = encodeUrl(callbackUrl);
  const consumerKey = process.env.TWITTER_CONSUMER_KEY;
  const consumerSecret = process.env.TWITTER_CONSUMER_SECRET;
  const timestamp = new Date() / 1000;
  const uuid = uuidv4();

  const parameters = {
    oauth_callback: encodedCallbackUrl,
		oauth_consumer_key : consumerKey,
		oauth_nonce : uuid,
		oauth_timestamp : timestamp,
		oauth_signature_method : 'HMAC-SHA1',
		oauth_version : '1.0'
  };

  var oauth =
    { callback: callbackUrl
    , consumer_key: consumerKey
    , consumer_secret: consumerSecret
    }
  , url = 'https://api.twitter.com/oauth/request_token'
  ;
  request.post({url:url, oauth:oauth}, function (e, r, body) {
    // Ideally, you would take the body in the response
    // and construct a URL that a user clicks on (like a sign in button).
    // The verifier is only available in the response after a user has
    // verified with twitter that they are authorizing your app.
    console.log('Does this work');
    console.log(body);
    var req_data = qs.parse(body);
    app.locals.magic_token_secret = req_data.oauth_token_secret;
    console.log('trying to save the magic');
    console.log(app.locals.magic_token_secret);
    var uri = 'https://api.twitter.com/oauth/authenticate'
      + '?' + qs.stringify({oauth_token: req_data.oauth_token})
    createTargetedMessage(req, uri);
  })
};

app.get('/authsuccess', function (req, res) {
  res.status(200).end();
  // step 3
  // after the user is redirected back to your server
  const consumerKey = process.env.TWITTER_CONSUMER_KEY;
  const consumerSecret = process.env.TWITTER_CONSUMER_SECRET;
  var magic_token_secret = app.locals.magic_token_secret;
  var auth_data = req.query
  , oauth =
    { consumer_key: consumerKey
    , consumer_secret: consumerSecret
    , token: auth_data.oauth_token
    , token_secret: magic_token_secret
    , verifier: auth_data.oauth_verifier
    }
  , url = 'https://api.twitter.com/oauth/access_token'
  ;
  request.post({url:url, oauth:oauth}, function (e, r, body) {
    // ready to make signed requests on behalf of the user
    var qString = require('querystring')
      , perm_data = qString.parse(body)
      , oauth =
        { consumer_key: consumerKey
        , consumer_secret: consumerSecret
        , token: perm_data.oauth_token
        , token_secret: perm_data.oauth_token_secret
        }
      , url = 'https://api.twitter.com/1.1/users/show.json'
      , qs =
        { screen_name: perm_data.screen_name
        , user_id: perm_data.user_id
        }
      ;
    request.get({url:url, oauth:oauth, qs:qs, json:true}, function (e, r, user) {
      console.log('Twitter user logged in:');
      console.log(user);
    });
  });

});

// Authenticate Application
const authenticateApp = (callback) => {

  // Authentication API
  const authenticationAPI = 'oauth/token';

  const authenticationOptions = {
    "method": "POST",
    "url": `${watsonWork}/${authenticationAPI}`,
    "auth": {
      "user": appId,
      "pass": appSecret
    },
    "form": {
      "grant_type": "client_credentials"
    }
  };

  request(authenticationOptions, (err, response, body) => {
    // If can't authenticate just return
    if (response.statusCode != 200) {
      console.log("Error authentication application. Exiting.");
      process.exit(1);
    }
    callback(JSON.parse(body).access_token);
  });
};

// Send message to Watson Workspace
const sendMessage = (spaceId, message) => {

  // Spaces API
  const spacesAPI = `v1/spaces/${spaceId}/messages`;

  // Photos API
  const photosAPI = `photos`;

  // Format for sending messages to Workspace
  const messageData = {
    type: "appMessage",
    version: 1.0,
    annotations: [
      {
        type: "generic",
        version: 1.0,
        color: "#1DA1F2",
        title: "Your Tweet",
        text: message
      }
    ]
  };

  // Authenticate application and send message.
  authenticateApp( (jwt) => {

    const sendMessageOptions = {
      "method": "POST",
      "url": `${watsonWork}/${spacesAPI}`,
      "headers": {
        "Authorization": `Bearer ${jwt}`
      },
      "json": messageData
    };

    request(sendMessageOptions, (err, response, body) => {
      if(response.statusCode != 201) {
        console.log("Error posting twitter information.");
        console.log(response.statusCode);
        console.log(err);
      }
    });
  });
};

// Ensure we can parse JSON when listening to requests
app.use(bodyParser.json());

app.get('/', (req, res) => {
  res.send('IBM Watson Workspace app for Twitter is alive and happy!');
});

const createTargetedMessage = (req, uri) => {
  const annotation = JSON.parse(req.body.annotationPayload);
  const conversationId = annotation.conversationId;
  const targetDialogId = annotation.targetDialogId;
  const targetUserId = req.body.userId;
  const spaceId = req.body.spaceId;

  console.log('trying to create a targeted message');
  authenticateApp(jwt => {
    if (jwt) {

      const annotations = `{
        genericAnnotation: {
          title: "Sample Title",
          text: "Sample Body",
          buttons: [
            {
              postbackButton: {
                title: "Sample Button",
                id: "Sample_Button",
                style: PRIMARY
              }
            }
          ]
        }
      }`;

      const card = [
        `
          {
            type: CARD,
            cardInput: {
              type: INFORMATION,
              informationCardInput: {
                title: "TwitterBot",
                subtitle: "",
                text: "${uri}",
                date: "${new Date().getTime()}",
                buttons: []
              }
            }
          }
        `
      ];

      const targetedMessage = `mutation {
        createTargetedMessage( input: {
          conversationId: "${conversationId}",
          targetDialogId: "${targetDialogId}",
          targetUserId: "${targetUserId}",
          annotations: [${annotations}],
          attachments: [${card}]
        })
        {
          successful
        }
      }
    `;

      console.log(`   sending targeted message: ${targetedMessage}`);
      request({
        url: `${WWS_GRAPHQL_URL}`,
        method: "POST",
        headers: {
          "Content-Type": "application/graphql",
          "x-graphql-view": "PUBLIC, BETA, EXPERIMENTAL",
          jwt: jwt
        },
        body: targetedMessage
      }, (err, response, graphqlbody) => {
        console.log(`   graphql status code:[${response.statusCode}] response:[${graphqlbody}]`);
        if (err || response.statusCode !== 200) console.log(err);
      });
    } else {
      console.log(`  could not authenticate`);
    }
  });
}


// This is callback URI that Watson Workspace will call when there's a new message created
app.post('/webhook', validateEvent, (req, res) => {
  res.status(200).end();
  const annotation = 'message-annotation-added';
  const actionSelected = 'actionSelected';
  console.log('annotation type');
  console.log(req.body.annotationType);
  console.log(req.body);
  if(annotation === req.body.type && actionSelected === req.body.annotationType) {
    console.log('will this stop');

    authenticateTwitter(req, (token) => {
      console.log('We called authenticate twitter');
    });

    return;
  
  } else {
    // Check if the first part of the message is '@twitter'.
    // This lets us "listen" for the '@twitter' keyword.
    if (req.body.content.indexOf(webhookKeyword) != 0) {
      ignoreMessage(res);
      return;
    }

    // Send status back to Watson Work to confirm receipt of message
    res.status(200).end();

    // Id of space where outbound event originated from.
    const spaceId = req.body.spaceId;

    // Parse twitter query from message body.
    // Expected format: <keyword> <twitter query>
    const twitterPost = req.body.content.replace('@twitter', '');
    console.log('About to tweet: \'' + twitterPost + '\'');

    var messageToPost = "Just tweeted \"" + twitterPost + "\" on your behalf!";

    const twitter_auth = {
      consumer_key: process.env.TWITTER_CONSUMER_KEY,
      consumer_secret: process.env.TWITTER_CONSUMER_SECRET,
      access_token_key: process.env.TWITTER_ACCESS_TOKEN_KEY,
      access_token_secret: process.env.TWITTER_ACCESS_TOKEN_SECRET
    }

    const client = new Twitter(twitter_auth);

      
    console.log('pretend I tweeted');
    // client.post('statuses/update', {status: twitterPost},  function(error, tweet, response) {
    //   if(error) throw error;

    //   console.log("Tweeting for you!");
    //   sendMessage(spaceId, messageToPost);
    // });
    }
});

// Kickoff the main process to listen to incoming requests
app.listen(process.env.PORT || 3000, () => {
  console.log('Twitter app is listening on the port');
});
