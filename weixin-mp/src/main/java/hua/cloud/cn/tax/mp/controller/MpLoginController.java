package hua.cloud.cn.tax.mp.controller;

import cn.hutool.json.JSONObject;
import hua.cloud.cn.tax.mp.util.WXUtil;
import io.swagger.annotations.ApiOperation;
import org.springframework.web.bind.annotation.*;

/**
 * @author ouzhx on 2018/8/17.
 */
@RestController
@RequestMapping("/mp")
public class MpLoginController {

    @ApiOperation("使用wx.login() 获取的code换取小程序标识信息")
    @GetMapping("login/{code}")
    public String doLogin(@PathVariable String code) {
        return WXUtil.Tax.doLogin(code);
    }

    @ApiOperation(value = "小程序数据解密", notes = "返回数据{'status':'1','msg':'解密成功','userInfo':'解密后的用户信息'}")
    @PostMapping("decode/{openId}")
    public JSONObject decodeData(@PathVariable String openId, @RequestParam String encryptedData, @RequestParam String iv) {
        return WXUtil.Tax.decodeData(openId, encryptedData, iv);
    }
}
