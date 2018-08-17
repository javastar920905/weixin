package hua.cloud.cn.tax.mp.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author ouzhx on 2018/8/17.
 */
@RestController
@RequestMapping("/")
public class IndexController {

    @GetMapping("/")
    public String hello() {
        return "hello";
    }
}
