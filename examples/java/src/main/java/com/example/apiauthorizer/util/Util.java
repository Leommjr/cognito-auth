package com.example.apiauthorizer.util;

import org.springframework.util.ResourceUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Properties;
import java.io.File;

public class Util {

    public static Properties fetchProperties(){
        Properties properties = new Properties();
        try {
            File file = ResourceUtils.getFile("classpath:application.properties");
            InputStream in = Files.newInputStream(file.toPath());
            properties.load(in);
        } catch (IOException ignored) {
        }
        return properties;
    }
}