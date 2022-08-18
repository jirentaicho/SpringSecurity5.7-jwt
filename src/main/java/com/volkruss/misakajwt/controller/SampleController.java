package com.volkruss.misakajwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleController {

    @GetMapping("/get")
    public String getSample(){
        return "sample GET is done";
    }

    @PostMapping("/post")
    public String postSample(){
        return "sample POST is done";
    }
}