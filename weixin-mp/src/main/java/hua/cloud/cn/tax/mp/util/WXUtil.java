package hua.cloud.cn.tax.mp.util;

import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import org.apache.tomcat.util.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author ouzhx on 2018/8/17.
 * 微信小程序工具类
 */
public class WXUtil {
    /**
     * 登陆校验url
     * 参考文档: https://developers.weixin.qq.com/miniprogram/dev/api/api-login.html#wxloginobject
     * <p>
     * 1 小程序调用wx.login() 获取 临时登录凭证code ，并回传到开发者服务器。
     * <p>
     * 2  开发者服务器以code换取 用户唯一标识openid 和 会话密钥session_key。
     * <p>
     * 会话密钥session_key 是对用户数据进行加密签名的密钥。为了应用自身的数据安全，开发者服务器不应该把会话密钥下发到小程序，也不应该对外提供这个密钥。
     */
    private static final String login_verify_url = "https://api.weixin.qq.com/sns/jscode2session?appid={APPID}&secret={SECRET}&js_code={JSCODE}&grant_type=authorization_code";

    //存储用户登录信息
    private static final Map<String, String> tax_UserMap = new HashMap<>();


    public static class Tax {
        static String appid = "";
        static String secret = "";

        static String buildLoginVeriifyUrl(String code) {
            return login_verify_url.replace("{APPID}", appid).replace("{SECRET}", secret).replace("{JSCODE}", code);
        }


        /**
         * 小程序端调用登录方法前一定要 调用wx.checkSession(OBJECT),校验用户当前session_key是否有效:
         * 1 避免反复调用商户login接口
         * 2  wx.login()调用时，用户的session_key会被更新而致使旧session_key失效,导致后期接口数据的解密失败。
         * <p>
         * <p>
         * 参考文档: https://developers.weixin.qq.com/miniprogram/dev/api/signature.html#wxchecksessionobject
         * wx.checkSession({
         * success: function(){
         * //session_key 未过期，并且在本生命周期一直有效
         * },
         * fail: function(){
         * // session_key 已经失效，需要重新执行登录流程
         * wx.login() //重新登录
         * ....
         * }
         * })
         *
         * @param code
         * @return
         */
        public static String doLogin(String code) {
            String content = HttpUtil.get(buildLoginVeriifyUrl(code));
            JSONObject json = JSONUtil.parseObj(content);
            String openId = json.getStr("openid");
            String session_key = json.getStr("session_key");

            //todo 自定义登录状态与open_id session_key关联 (存入redis,openId 存在则代表登录成功)
            tax_UserMap.put(openId, session_key);
            return openId;
        }


        /**
         * 数据解密
         * 获取电话号码示例:
         * https://developers.weixin.qq.com/miniprogram/dev/api/getPhoneNumber.html
         * <p>
         * 小程序调用getPhoneNumber 微信后会返回encryptedData(包括敏感数据在内的完整用户信息的加密数据)和iv(加密算法的初始向量)
         * <p>
         * <p>
         * /**
         * * 获取小程序开放数据(如手机号,昵称等)
         * * 参考文档: https://developers.weixin.qq.com/miniprogram/dev/api/signature.html#wxchecksessionobject
         * * <p>
         * * 签名校验以及数据加解密涉及用户的会话密钥session_key。
         * * 开发者应该事先通过 wx.login 登录流程获取会话密钥 session_key 并保存在服务器。为了数据不被篡改，开发者不应该把session_key传到小程序客户端等服务器外的环境。
         * * <p>
         * * 签名校验demo:
         * * 1 通过调用接口（如 wx.getUserInfo）获取数据时，接口会同时返回 rawData、signature，其中 signature = sha1( rawData + session_key )
         * * 2 开发者将 signature、rawData 发送到开发者服务器进行校验。服务器利用用户对应的 session_key 使用相同的算法计算出签名 signature2 ，比对 signature 与 signature2 即可校验数据的完整性。
         * * <p>
         * * 会话密钥session_key有效性,开发者如果遇到因为session_key不正确而校验签名失败或解密失败:
         * * 1 wx.login()调用时，用户的session_key会被更新而致使旧session_key失效。开发者应该在明确需要重新登录时才调用wx.login()，及时通过登录凭证校验接口更新服务器存储的session_key。
         * * 2 微信不会把session_key的有效期告知开发者。我们会根据用户使用小程序的行为对session_key进行续期。用户越频繁使用小程序，session_key有效期越长。
         * * 3 开发者在session_key失效时，可以通过重新执行登录流程获取有效的session_key。使用接口wx.checkSession()可以校验session_key是否有效，从而避免小程序反复执行登录流程。
         * * 4 当开发者在实现自定义登录态时，可以考虑以session_key有效期作为自身登录态有效期，也可以实现自定义的时效性策略
         *
         * @return
         */
        public static JSONObject decodeData(String openId, String encryptedData, String iv) {
            return decrypt(encryptedData, tax_UserMap.get(openId), iv);
        }

    }

    /**
     * 小程序数据解密算法封装
     *
     * @param encryptedData
     * @param session_key
     * @param iv
     */
    public static JSONObject decrypt(String encryptedData, String session_key, String iv) {
        Map map = new HashMap();
        try {
            byte[] resultByte = AES.decrypt(Base64.decodeBase64(encryptedData),
                    Base64.decodeBase64(session_key),
                    Base64.decodeBase64(iv));
            if (null != resultByte && resultByte.length > 0) {
                String userInfo = new String(resultByte, "UTF-8");
                map.put("status", "1");
                map.put("msg", "解密成功");
                map.put("userInfo", userInfo);
            } else {
                map.put("status", "0");
                map.put("msg", "解密失败");
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return JSONUtil.parseObj(map);
    }


}
