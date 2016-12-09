<?php

namespace SocialiteProviders\Weixin2;

use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\Contracts\ConfigInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;
use Symfony\Component\HttpFoundation\RedirectResponse;

class Provider extends AbstractProvider implements ProviderInterface
{
    /**
     * Provider标识
     */
    const IDENTIFIER = 'WEIXIN';

    //应用的openid
    protected $openId;
    //是否为无状态请求，默认改为true，因为用cookie验证state，而不是session
    protected $stateless = true;
    //定义授权作用域，默认值改成snsapi_login
    protected $scopes = ['snsapi_login'];
    //代理授权回调的地址
    protected $proxy_url = '';
    //PC端还是移动端
    protected $device = 'pc';
    //授权地址
    protected $auth_url = '';
    //授权state的cookie名称
    protected $state_cookie_name = 'wx_state_cookie';
    //授权state的cookie有效时长
    protected $state_cookie_time = 5 * 60;

    /**
     * 拼接授权链接地址
     * @param string $url
     * @param string $state
     * @return string
     */
    protected function buildAuthUrlFromBase($url, $state)
    {
        $query = http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);

        return $url . '?' . $query . '#wechat_redirect';
    }

    /**
     * 获取access token的api地址
     * @return string
     */
    protected function getTokenUrl()
    {
        return 'https://api.weixin.qq.com/sns/oauth2/access_token';
    }

    /**
     * 用token获取userinfo
     * @param string $token
     * @return mixed
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get('https://api.weixin.qq.com/sns/userinfo', [
            'query' => [
                'access_token' => $token,
                'openid' => $this->openId,
                'lang' => 'zh_CN',
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * 将微信返回的userinfo转成Auth/User对象
     * @param array $user
     * @return $this
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'openid' => $user['openid'],
            'unionid' => $user['unionid'],
            'nickname' => isset($user['nickname']) ? $user['nickname'] : null,
            'avatar' => isset($user['headimgurl']) ? $user['headimgurl'] : null,
            'name' => null,
            'email' => null,
        ]);
    }

    /**
     * 获取调用access token api时的参数
     * @param string $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        return [
            'appid' => $this->clientId, 'secret' => $this->clientSecret,
            'code' => $code, 'grant_type' => 'authorization_code',
        ];
    }

    /**
     * 生成state参数
     * @return string
     */
    protected function getState()
    {
        return uniqid() . rand(1000, 9999);
    }

    /**
     * 用于校验state
     * 返回true表示state无效，返回false表示state校验正确
     * @return bool
     */
    protected function hasInvalidState()
    {
        if (isset($_COOKIE[$this->state_cookie_name]) &&
            $_COOKIE[$this->state_cookie_name] ==
            self::getEncryptState($this->request->input('state'))
        ) {
            return false;
        }

        return true;
    }

    /**
     * 对$state做加密处理
     * @param $state
     * @return string
     */
    protected function getEncryptState($state)
    {
        return md5($state);
    }

    /**
     * 获取授权链接
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state)
    {
        if (empty($this->proxy_url)) {
            if ($this->device == 'pc') {
                $this->auth_url = 'https://open.weixin.qq.com/connect/qrconnect';
            } else {
                $this->auth_url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
            }
        } else {
            $this->auth_url = $this->proxy_url;
        }

        return $this->buildAuthUrlFromBase($this->auth_url, $state);
    }

    //===========================================================
    //以下为public方法，外部可根据需要调用
    //===========================================================

    /**
     * 获取授权地址中要传递的参数
     * 如果采用代理授权地址，则添加device的标识
     * @param null $state
     * @return array
     */
    protected function getCodeFields($state = null)
    {
        $options = [
            'appid' => $this->clientId, 'redirect_uri' => $this->redirectUrl,
            'response_type' => 'code',
            'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
            'state' => $state,
        ];

        if (!empty($this->proxy_url)) {
            $options['device'] = $this->device;
        }

        return $options;
    }

    /**
     * 获取access token
     * @param string $code
     * @return mixed
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->get($this->getTokenUrl(), [
            'query' => $this->getTokenFields($code),
        ]);

        $this->credentialsResponseBody = json_decode($response->getBody(), true);
        $this->openId = $this->credentialsResponseBody['openid'];

        return $this->credentialsResponseBody;
    }

    /**
     * 测试方法：校验state参数
     * @return bool
     */
    public function stateInvalid()
    {
        return $this->hasInvalidState();
    }

    /**
     * 重定向并将state参数写到cookie里面去，而不是采用session
     * @return string
     */
    public function redirect()
    {
        $state = $this->getState();

        $response = new RedirectResponse($this->getAuthUrl($state), 302, [
            'Set-Cookie' => implode('', [
                $this->state_cookie_name,
                '=',
                $this->getEncryptState($state),
                "; path=/; domain=",
                $_SERVER['HTTP_HOST'],
                "; expires=" . gmstrftime("%A, %d-%b-%Y %H:%M:%S GMT", time() + $this->state_cookie_time),
                "; Max-Age=" . $this->state_cookie_time,
                "; httponly"
            ])
        ]);

        return $response;
    }

    /**
     * 定义需要额外解析的参数名
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return ['proxy_url', 'device', 'state_cookie_name', 'state_cookie_time'];
    }

    /**
     * 提供给外部定义scope
     * @param array $scopes
     * @return $this
     */
    public function scopes(array $scopes)
    {
        $this->scopes = array_unique($scopes);

        return $this;
    }

    /**
     * 重写setConfig方法，在原有的基础上，增加对
     * 'proxy_url', 'device', 'state_cookie_name', 'state_cookie_time'
     * 这四个参数的解析
     * @param ConfigInterface $config
     * @return $this
     */
    public function setConfig(ConfigInterface $config)
    {
        $config = $config->get();

        $this->config = $config;
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUrl = $config['redirect'];
        $this->proxy_url = $config['proxy_url'];

        if (isset($config['proxy_url'])) {
            $this->proxy_url = $config['proxy_url'];
        }
        if (isset($config['device'])) {
            $this->device = $config['device'];
        }
        if (isset($config['state_cookie_name'])) {
            $this->state_cookie_name = $config['state_cookie_name'];
        }
        if (isset($config['state_cookie_time'])) {
            $this->state_cookie_time = $config['state_cookie_time'];
        }

        return $this;
    }

    public function getOpenId()
    {
        return $this->openId;
    }

    public function setOpenId($openId)
    {
        $this->openId = $openId;
        return $this;
    }

    public function getScopes()
    {
        return $this->scopes;
    }

    public function setScopes($scopes)
    {
        $this->scopes = $scopes;
        return $this;
    }

    public function getProxyUrl()
    {
        return $this->proxy_url;
    }

    public function setProxyUrl($proxy_url)
    {
        $this->proxy_url = $proxy_url;
        return $this;
    }

    public function getDevice()
    {
        return $this->device;
    }

    public function setDevice($device)
    {
        $this->device = $device;
        return $this;
    }

    public function getStateCookieName()
    {
        return $this->state_cookie_name;
    }

    public function setStateCookieName($state_cookie_name)
    {
        $this->state_cookie_name = $state_cookie_name;
        return $this;
    }

    public function getStateCookieTime()
    {
        return $this->state_cookie_time;
    }

    public function setStateCookieTime($state_cookie_time)
    {
        $this->state_cookie_time = $state_cookie_time;
        return $this;
    }

    public function getClientId()
    {
        return $this->clientId;
    }

    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
        return $this;
    }

    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    public function getRedirectUrl()
    {
        return $this->redirectUrl;
    }

    public function setRedirectUrl($redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;
        return $this;
    }
}
