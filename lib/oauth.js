var urllib = require('urllib');
var extend = require('util')._extend;
var querystring = require('querystring');

var ComponentAccessToken = function (data) {
  if (!(this instanceof ComponentAccessToken)) {
    return new ComponentAccessToken(data);
  }
  this.component_access_token = data.component_access_token;
  this.expires_at = data.expires_at;
};


/**
 * 检查ComponentAccessToken是否有效
 */
ComponentAccessToken.prototype.isValid = function () {
  return !!this.component_access_token && (new Date().getTime()) < this.expires_at;
};


/**
 * 根据appid和appsecret创建Auth的构造函数
 * @param {String} appid 在开放平台申请得到的第三方平台appid
 * @param {String} appsecret 在开放平台申请得到的第三方平台appsecret
 * @param {Function} getVerifyTicket 获取全局component_verify_ticket的方法，建议存放在缓存中, 必填项
 * @param {Function} getComponentToken 获取全局component_access_token的方法，选填项，多进程状态下应该存放在缓存中
 * @param {Function} saveComponentToken获取全局component_access_token的方法，选填项，多进程状态下应该存放在缓存中
 */
var OAuth = function (appid, appsecret, getVerifyTicket, getComponentToken, saveComponentToken) {
  this.appid = appid;
  this.appsecret = appsecret;
  this.getVerifyTicket = getVerifyTicket;
  this.getComponentToken = getComponentToken || function *() {
        return this.store;
      };
  if (!saveComponentToken && process.env.NODE_ENV === 'production') {
    console.warn("Please dont save oauth token into memory under production");
  }
  this.saveComponentToken = saveComponentToken || function * (token) {
        this.store = token;
      };
  this.prefix = 'https://api.weixin.qq.com/cgi-bin/component/';
  this.snsPrefix = 'https://api.weixin.qq.com/sns/';
  this.defaults = {};
};

/**
 * 用于设置urllib的默认options
 *
 * Examples:
 * ```
 * oauth.setOpts({timeout: 15000});
 * ```
 * @param {Object} opts 默认选项
 */
OAuth.prototype.setOpts = function (opts) {
  this.defaults = opts;
};

/*!
 * urllib的封装
 *
 * @param {String} url 路径
 * @param {Object} opts urllib选项
 */
OAuth.prototype.request = function * (url, opts) {
  var options = {};
  extend(options, this.defaults);
  opts || (opts = {});
  for (var key in opts) {
    if (key !== 'headers') {
      options[key] = opts[key];
    } else {
      if (opts.headers) {
        options.headers = options.headers || {};
        extend(options.headers, opts.headers);
      }
    }
  }

  var result;
  try {
    result = yield urllib.requestThunk(url, options);
  } catch (err) {
    err.name = 'WeChatAPI' + err.name;
    throw err;
  }

  var data = result.data;

  if (data.errcode) {
    var err = new Error(data.errmsg);
    err.name = 'WeChatAPIError';
    err.code = data.errcode;
    throw err;
  }

  return data;
};


/*
 * 根据创建auth实例时传入的appid和appsecret获取component_access_token
 * 进行后续所有API调用时，需要先获取这个token
 *
 * 应用开发者不需直接调用本API
 *
 * @param {Function} callback 回调函数
 */
OAuth.prototype.getComponentAccessToken = function * (callback) {
  var url = this.prefix + 'api_component_token';
  var verifyTicket = yield this.getVerifyTicket();
  var params = {
    component_appid: this.appid,
    component_appsecret: this.appsecret,
    component_verify_ticket: verifyTicket
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  var token = yield this.request(url, args);
  var expireTime = (new Date().getTime()) + (token.expires_in - 100) * 1000;
  token.expires_at = expireTime;
  yield this.saveComponentToken(token);
  return token;
};

/*!
 * 需要component_access_token的接口调用如果采用ensureAccessToken进行封装后，就可以直接调用。
 * 无需依赖getComponentAccessToken为前置调用。
 * 应用开发者无需直接调用此API。
 *
 * Examples:
 * ```
 * auth.preRequest(method, arguments);
 * ```
 * @param {Function} method 需要封装的方法
 * @param {Array} args 方法需要的参数
 */

OAuth.prototype.ensureAccessToken = function * () {
  // 调用用户传入的获取token的异步方法，获得token之后使用（并缓存它）。
  var token = yield this.getComponentToken();
  var accessToken;
  if (token && (accessToken = ComponentAccessToken(token)).isValid()) {
    return accessToken;
  }
  return yield this.getComponentAccessToken();
};

/*
 * 获取预授权码pre_auth_code
 *
 * Result:
 * ```
 * {"pre_auth_code": "PRE_AUTH_CODE", "expires_in": 600}
 * ```
 * 开发者需要检查预授权码是否过期
 */

OAuth.prototype.getPreAuthCode = function * () {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_create_preauthcode?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 使用授权码换取公众号的接口调用凭据和授权信息
 * 这个接口需要在用户授权回调URI中调用，拿到用户公众号的调用
 * 凭证并保持下来（缓存or数据库）
 * 仅需在授权的时候调用一次
 *
 * Result:
 * ```
 * {
 *   "authorization_info": {
 *     "authorizer_appid": "wxf8b4f85f3a794e77",
 *     "authorizer_access_token": "AURH_ACCESS_CODE",
 *     "expires_in": 7200,
 *     "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
 *     "func_info": [
 *     ]
 *   }
 * }
 *
 * @param {String} auth_code 授权码
 */

OAuth.prototype.getAuthToken = function * (auth_code) {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_query_auth?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid,
    authorization_code: auth_code
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};



/*
 * 获取（刷新）授权公众号的接口调用凭据（Token）
 * 这个接口应该由自动刷新授权授权方令牌的代码调用
 *
 * Result:
 * ```
 * {
 *   "authorizer_access_token": "AURH_ACCESS_CODE",
 *   "expires_in": 7200,
 *   "authorizer_refresh_token": "AUTH_REFRESH_TOKEN",
 * }
 *
 * @param {String} authorizer_appid 授权方appid
 * @param {String} authorizer_refresh_token 授权方的刷新令牌
 */
OAuth.prototype.refreshAuthToken = function * (authorizer_appid, authorizer_refresh_token) {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_authorizer_token?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid,
    authorizer_appid: authorizer_appid,
    authorizer_refresh_token: authorizer_refresh_token
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 获取授权方的公众账号基本信息
 *
 * @param {String} authorizer_appid 授权方appid
 */
OAuth.prototype.getAuthInfo = function * (authorizer_appid) {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_get_authorizer_info?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid,
    authorizer_appid: authorizer_appid
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 获取授权方的选项设置信息
 *
 * @param {String} authorizer_appid 授权方appid
 * @param {String} option_name 选项名称
 */
OAuth.prototype.getAuthOption = function * (authorizer_appid, option_name) {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_get_authorizer_option?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid,
    authorizer_appid: authorizer_appid,
    option_name: option_name
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 设置授权方的选项信息
 *
 * @param {String} authorizer_appid 授权方appid
 * @param {String} option_name 选项名称
 * @param {String} option_value 选项值
 */
OAuth.prototype.setAuthOption = function * (authorizer_appid, option_name, option_value) {
  var token = yield this.ensureAccessToken();
  var url = this.prefix + 'api_set_authorizer_option?component_access_token=' + token.component_access_token;
  var params = {
    component_appid: this.appid,
    authorizer_appid: authorizer_appid,
    option_name: option_name,
    option_value: option_value
  };
  var args = {
    method: 'post',
    data: params,
    dataType: 'json',
    contentType: 'json'
  };
  return yield this.request(url, args);
};


/****************** 以下是网页授权相关的接口******************/

/**
 * 获取授权页面的URL地址
 * @param {String} appid 授权公众号的appid
 * @param {String} redirect 授权后要跳转的地址
 * @param {String} state 开发者可提供的数据
 * @param {String} scope 作用范围，值为snsapi_userinfo和snsapi_base，前者用于弹出，后者用于跳转
 */
OAuth.prototype.getOAuthURL = function (appid, redirect, state, scope) {
  var url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
  var info = {
    appid: appid,
    redirect_uri: redirect,
    response_type: 'code',
    scope: scope || 'snsapi_base',
    state: state || '',
    component_appid: this.appid
  };

  return url + '?' + querystring.stringify(info) + '#wechat_redirect';
};


/*
 * 根据授权获取到的code，换取access_token和openid
 *
 * @param {String} appid 授权公众号的appid
 * @param {String} code 授权获取到的code
 */
OAuth.prototype.getOAuthAccessToken = function * (appid, code) {
  var token = yield this.ensureAccessToken();
  var url = this.snsPrefix + 'oauth2/component/access_token';
  var params = {
    appid: appid,
    code: code,
    grant_type: 'authorization_code',
    component_appid: this.appid,
    component_access_token: token.component_access_token
  };
  var args = {
    method: 'get',
    data: params,
    dataType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 刷新网页授权的access_token
 *
 * @param {String} appid 授权公众号的appid
 * @param {String} refresh_token 授权刷新token
 */
OAuth.prototype.refreshOAuthAccessToken = function * (appid, refresh_token) {
  var token = yield this.ensureAccessToken();
  var url = this.snsPrefix + 'oauth2/component/refresh_token';
  var params = {
    appid: appid,
    refresh_token: refresh_token,
    grant_type: 'refresh_token',
    component_appid: this.appid,
    component_access_token: token.component_access_token
  };
  var args = {
    method: 'get',
    data: params,
    dataType: 'json'
  };
  return yield this.request(url, args);
};


/*
 * 通过access_token获取用户基本信息
 *
 * @param {String} openid 授权用户的唯一标识
 * @param {String} access_token 网页授权接口调用凭证
 * @param {String} lang 返回国家地区语言版本，zh_CN 简体，zh_TW 繁体，en 英语
 */
OAuth.prototype.getUserInfo = function * (openid, access_token, lang) {
  var url = this.snsPrefix + 'userinfo';
  var params = {
    openid: openid,
    access_token: access_token,
    lang: lang || 'en'
  };
  var args = {
    method: 'get',
    data: params,
    dataType: 'json'
  };
  return yield this.request(url, args);
};

OAuth.prototype.getLoginPage = function * (redirect_url) {
  var pre_auth_code = yield this.getPreAuthCode();
  var url = 'https://mp.weixin.qq.com/cgi-bin/componentloginpage';
  var info = {
    component_appid: this.appid,
    pre_auth_code: pre_auth_code.pre_auth_code,
    redirect_url: redirect_url
  };

  return url + '?' + querystring.stringify(info);
};

module.exports = OAuth;
