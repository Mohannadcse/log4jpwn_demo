package com.sensepost.log4jpwn;


import static spark.Spark.*;

public class App2 {

    public static void main(String[] args) {

        port(8080);

	get("/app2", (req, res)->"Hello, world, from App2");
    }
}
