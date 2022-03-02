import requests
import random
import re


class APClassroom:
    def __init__(self, username:str, password:str):
        self.deviceFingerprint:str =
        self.requestSession = requests.Session()
        """use a request session to keep the same connection open"""
        self.deviceFingerprint: str =
        self.oktaAgent:         str = "okta-signin-widget-5.9.4"
        self.__username:        str = username
        self.__password:        str = password
        self.token:             str = self.login()
        """Will return the bearer token, used to authenticate"""



    def login(self) -> str:
        nonce = self.requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce").json()['nonce']
        loginUrl: str = f"https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id=0oa3koxakyZGbffcq5d7&response_type=code&scope=openid+email+profile&redirect_uri=https://account.collegeboard.org/login/exchangeToken&state=cbAppDurl&nonce={nonce}"
        #https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id=0oa3koxakyZGbffcq5d7&response_type=code&scope=openid+email+profile&redirect_uri=https://account.collegeboard.org/login/exchangeToken&state=cbAppDurl&nonce=MTY0NjIyODM2MzYyNg==

        self.requestSession.get()
        '''
        <!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="none" />

	<!-- Apricot 4.4.10  -->
    <link href="//atlas.collegeboard.org/apricot/prod/4.4.10/main.css" rel="stylesheet" />

    <!-- CB Adobe Web Analytics Lib -->
	<script src="//assets.adobedtm.com/f740f8a20d94/1dcfc2687ba3/launch-9227a8742d03.min.js" async></script>
    <title>College Board - Sign In</title>
    <!-- Core widget js and css -->
<script type="text/javascript"
        src="https://ok12static.oktacdn.com/assets/js/sdk/okta-signin-widget/5.9.4/js/okta-sign-in.min.js"></script>
<link rel="stylesheet"
      type="text/css"
      href="https://ok12static.oktacdn.com/assets/js/sdk/okta-signin-widget/5.9.4/css/okta-sign-in.min.css">

<!-- Customizable css theme options. Link your own stylesheet or override styles inline. -->
<link rel="stylesheet"
      type="text/css" href="">

<!-- styles for custom sign in -->
<link rel="stylesheet" type="text/css" href="https://ok12static.oktacdn.com/assets/loginpage/css/custom-signin.bb8f4ce4363dd17160adb27f2ab5f478.css">


	<!-- Apricot 4.4.10 - Okta -->
    <link href="//atlas.collegeboard.org/apricot/prod/4.4.10/okta.css" rel="stylesheet" />

  </head>

  <body class="cb-okta">
    <!--
        "OktaUtil" defines a global OktaUtil object
        that contains methods used to complete the Okta login flow.
     -->

<div id="okta-sign-in" class="auth-container main-container unsupported-message-container" style="display:none">
    <div id="unsupported-cookie" class="unsupported-message" style="display:none">
        <h2 class="o-form-head">Cookies are required</h2>
        <p>Cookies are disabled on your browser. Please enable Cookies and refresh this page.</p>
        <a class="button button-primary" target="_blank" href=".">
            Refresh
        </a>
    </div>
</div>
<script type="text/javascript">
  var signInSuccessCallBackFunction;
  var oktaData = {"redirectUri":"https\x3A\x2F\x2Fprod.idp.collegeboard.org\x2Foauth2\x2Fv1\x2Fauthorize\x2Fredirect\x3Fokta_key\x3DCn60azPZCVRAkqeo5R0pXFET3cKHZIZuHDDSijNQ_oE","isMobileSso":false,"fromUri":"\x2Foauth2\x2Fv1\x2Fauthorize\x2Fredirect\x3Fokta_key\x3DCn60azPZCVRAkqeo5R0pXFET3cKHZIZuHDDSijNQ_oE","isMobileClientLogin":false,"requestContext":{"target":{"clientId":"0oa3koxakyZGbffcq5d7","name":"oidc_client","links":{},"label":"paLoginCloud\x20\x2D\x20Default","type":{}},"authentication":{"request":{"scope":"openid\x20email\x20profile","response_type":"code","state":"cbAppDurl","redirect_uri":"https\x3A\x2F\x2Faccount.collegeboard.org\x2Flogin\x2FexchangeToken","response_mode":"query"},"protocol":{},"amr":[],"client":{"name":"paLoginCloud\x20\x2D\x20Default","links":{},"id":"0oa3koxakyZGbffcq5d7"},"issuer":{"name":"cb\x2Dcustom\x2Dauth\x2Dserver","id":"aus3koy55cz6p83gt5d7","uri":"https\x3A\x2F\x2Fprod.idp.collegeboard.org\x2Foauth2\x2Faus3koy55cz6p83gt5d7"}}},"signIn":{"logoText":"College\x20Board\x20logo","language":"en","consent":{"cancel":function(){window.location.href='https\x3A\x2F\x2Fprod.idp.collegeboard.org\x2Flogin\x2Fstep\x2Dup\x2Fredirect\x3FstateToken\x3D003qVgUg3EoGI7TRdC3qHirJ8eMwDk5IJ635EfymJO';}},"i18n":{"en":{"mfa.challenge.password.placeholder":"Password","help":"Help","password.forgot.email.or.username.tooltip":"Enter\x20your\x20email","needhelp":"Need\x20help\x20signing\x20in\x3F","primaryauth.username.placeholder":"Email\x20Address","password.forgot.email.or.username.placeholder":"Enter\x20your\x20email","account.unlock.email.or.username.tooltip":"Enter\x20your\x20email","unlockaccount":"Unlock\x20account\x3F","account.unlock.email.or.username.placeholder":"Enter\x20your\x20email","primaryauth.password.placeholder":"Password","primaryauth.title":"Sign\x20In","forgotpassword":"Forgot\x20password\x3F"}},"relayState":"\x2Foauth2\x2Fv1\x2Fauthorize\x2Fredirect\x3Fokta_key\x3DCn60azPZCVRAkqeo5R0pXFET3cKHZIZuHDDSijNQ_oE","features":{"emailRecovery":true,"restrictRedirectToForeground":true,"deviceFingerprinting":true,"consent":true,"useDeviceFingerprintForSecurityImage":true,"customExpiredPassword":true,"router":true,"showPasswordToggleOnSignInPage":true,"securityImage":false,"autoPush":true,"smsRecovery":true,"idpDiscovery":true,"selfServiceUnlock":true,"webauthn":true,"showPasswordRequirementsAsHtmlList":true,"registration":false,"rememberMe":true,"callRecovery":false,"multiOptionalFactorEnroll":true},"baseUrl":"https\x3A\x2F\x2Fprod.idp.collegeboard.org","assets":{"baseUrl":"https\x3A\x2F\x2Fok12static.oktacdn.com\x2Fassets\x2Fjs\x2Fsdk\x2Fokta\x2Dsignin\x2Dwidget\x2F5.9.4"},"customButtons":[],"idpDiscovery":{"requestContext":"\x2Foauth2\x2Fv1\x2Fauthorize\x2Fredirect\x3Fokta_key\x3DCn60azPZCVRAkqeo5R0pXFET3cKHZIZuHDDSijNQ_oE"},"logo":"https\x3A\x2F\x2Fok12static.oktacdn.com\x2Ffs\x2Fbco\x2F1\x2Ffs03ir6072jIeBspy5d7","stateToken":"003qVgUg3EoGI7TRdC3qHirJ8eMwDk5IJ635EfymJO","helpLinks":{"help":"https\x3A\x2F\x2Fsupport.collegeboard.org\x2Fhelp\x2Dcenter\x2Faccount\x2Dhelp","forgotPassword":"","unlock":"","custom":[]},"piv":{}},"accountChooserDiscoveryUrl":"https\x3A\x2F\x2Flogin.okta.com\x2Fdiscovery\x2Fiframe.html"};

  var runLoginPage = function(fn) {
    var mainScript = document.createElement('script');
    mainScript.src = "https://ok12static.oktacdn.com/assets/js/mvc/loginpage/initLoginPage.pack.103f0a08c8f9401f5a348e6d81b34c6a.js";
    document.getElementsByTagName('head')[0].appendChild(mainScript);
    fn && mainScript.addEventListener('load', function () { setTimeout(fn, 1) });
  };

  var OktaUtil = {
    _addClass: function(el, className) {
      if(el) {
        var elementClasses = el.className.split(" ");
        if (elementClasses.indexOf(className) == -1) {
          el.className += " " + className;
        }
      }
    },

    _removeElement: function(el) {
      if(el) {
        el.parentNode.removeChild(el);
      }
    },

    _hideElement: function(el) {
      if(el) {
        el.style.display = 'none';
      }
    },

    addLoginContainerClass: function () {
      this._addClass(document.getElementById('okta-login-container'), 'login-container');
    },

    showUnsupportedCookieWarning: function () {
      document.getElementById('okta-sign-in').removeAttribute('style');
      document.getElementById('unsupported-cookie').removeAttribute('style');
    },

    removeUnsupportedCookieWarning: function () {
      this._removeElement(document.getElementById('okta-sign-in'));
    },

    hideOktaLoginContainer: function () {
      this._hideElement(document.getElementById('okta-login-container'));
    },

    isChromeOs:  function () {
      return /\bCrOS\b/.test(navigator.userAgent);
    },

    addChromeOSScript: function() {
      var chromeOSScript = document.createElement('script');
      chromeOSScript.src = "/js/google/users-1.0.js";
      document.getElementsByTagName('head')[0].appendChild(chromeOSScript);
    },

    getSignInWidgetConfig: function () {
        return oktaData.signIn;
    },

    completeLogin: function (res) {
      signInSuccessCallBackFunction(res);
    },

    getRequestContext: function () {
      return oktaData.requestContext;
    },

    setRedirectUri: function (uri) {
      oktaData.redirectUri = uri;
    },

    init: function () {
      if (!navigator.cookieEnabled) {
        this.showUnsupportedCookieWarning();
        this.hideOktaLoginContainer();
      } else {
        this.removeUnsupportedCookieWarning();

        // add class if app login banner is present
        if (oktaData.isAppBannerVisible) {
          this.addLoginContainerClass();
        }

        oktaData.isCustomSignIn = true;
        oktaData.hasChromeOSFeature = this.isChromeOs();
        if (oktaData.hasChromeOSFeature) {
          this.addChromeOSScript();
        }
        runLoginPage(function () {
          var res = OktaLogin.initLoginPage(oktaData);
          oktaData.signIn = res.signIn;
          signInSuccessCallBackFunction = res.signInSuccessCallbackFn;

        });
      }
    }
  };
  OktaUtil.init();
  //# sourceURL=OktaUtil.js
</script>


    <!-- CB Global Header -->
    <div id="header"></div>
    <!-- <div class="login-bg-image" style="background-image: none"></div>  -->
    <div id="okta-login-container"></div>

    <!-- CB Global Footer -->
    <div id="footer"></div>

    <!-- CB Apricot 4.x and Widget js -->
    <script>
      // declare apricot 4.x
      window.cb = window.cb || {};
      window.cb.apricot = window.cb.apricot || {};
      window.cb.apricot.version = "4.4.0";
      //identity settings
        window.cb.core = window.cb.core || {};
		window.cb.core.utils = window.cb.core.utils || {};
		window.cb.core.utils.DeploymentProfile = {
 		 iam: {
    		sessionCheck: false
  		 },
  			dataProtector: {
    		protectionEnabled: false
         }
        };
    </script>
    <script src="https://atlas.collegeboard.org/widgets/release/2021-04-27/main.js"></script>
    <script src="https://palogincloud-ui-pine.iam-prod.collegeboard.org/okta/cb_widgets.js"></script>

    <script type="text/javascript">
      // "config" object contains default widget configuration
      // with any custom overrides defined in your admin settings.
      var config = OktaUtil.getSignInWidgetConfig();

	 //test IdP for migration help
	 //	config.idps= [
 	 //	 { type: 'CB Migration App', text:'Get help migrating your account?', id: '0oasapfs7mdwXwn9m0h7' }
	 //	];
	 //	config.idpDisplay = "SECONDARY";

      var oktaRequstContext = OktaUtil.getRequestContext();

      cb_customizeLinks(config);
      cb_customizeTextLabels();
	  cb_customizeTextLabelsWithRequestContext(oktaRequstContext);

      // Render the Okta Sign-In Widget
      var oktaSignIn = new OktaSignIn(config);
      cb_customizeEventTracking(oktaSignIn);

      oktaSignIn.renderEl(
        {
          el: "#okta-login-container",
        },
        OktaUtil.completeLogin,
        function (error) {
          // Logs errors that occur when configuring the widget.
          // Remove or replace this with your own custom error handler.
          console.log(error.message, error);
        }
      );
    </script>
  </body>
</html>


        '''
        url = "https://prod.idp.collegeboard.org/api/v1/authn"
