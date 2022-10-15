package com.sensepost.log4jpwn;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import static spark.Spark.*;

public class App {

    public static void main(String[] args) {

        port(8080);

        get("/", (req, res) -> {
	        Logger logger = LogManager.getLogger(App.class.getName());
            String ua = req.headers("User-Agent");
            String pwn = req.queryParams("pwn");
            String pth = req.pathInfo();

            System.out.println("logging ua: " + ua);
            System.out.println("logging pwn: " + pwn);
            System.out.println("logging pth: " + pth);

            // trigger
            logger.error(ua);
            logger.error(pwn);
            logger.error(pth);

            return "ok: ua: " + ua + " " + "pwn: " + pwn + " pth:" + pth;
        });

	get("/hello", (req, res)->"Hello, world");
    }
}
