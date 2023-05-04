package com.example.multipartauthenticationApplication;

import java.io.*;

import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import multipartauthenticationlibrary.*;


@WebServlet(name = "LoginServlet", value = "/login-first")
public class LoginServlet extends  HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws  IOException{
        response.setContentType("application/json");
        PrintWriter writer = response.getWriter();

        String devOpt = request.getParameter("devOpt");
        if (devOpt.equals("CHAP")){
            writer.write(LoginLib.CHAPRandomValueJsonGenerator(request));
            writer.flush();
        }
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
        response.setContentType("application/json");

        String devOpt = request.getParameter("devOpt");

        PrintWriter writer = response.getWriter();

        String username = LoginLib.getUserNameFromRequest(request);

        if (devOpt.equals("PAP")){
            if (LoginLib.PAPResult(request,username,database.UserandPsw.get(username))
                    .equals("true")){

                JsonObject obj2 = new JsonObject();
                obj2.addProperty("statues", 302);
                obj2.addProperty("location", "./SecondAuth.html");
                GsonBuilder builder = new GsonBuilder();
                Gson gson = builder.create();
                writer.write(gson.toJson(obj2));
            }
            else {
                JsonObject obj2 = new JsonObject();
                obj2.addProperty("statues", 401);
                obj2.addProperty("message", "Username or Password wrong");
                GsonBuilder builder = new GsonBuilder();
                Gson gson = builder.create();
                writer.write(gson.toJson(obj2));
            }
        }
        if (devOpt.equals("CHAP")) {
            response.setContentType("application/json");
            String result = LoginLib.CHAPResult(request,
                    username,database.UserandPsw.get(username));

            if (result.equals("true")){

                response.setContentType("application/json");
                JsonObject obj1 = new JsonObject();
                obj1.addProperty("statues", 302);
                obj1.addProperty("location", "./SecondAuth.html");
                GsonBuilder builder = new GsonBuilder();
                Gson gson = builder.create();
                writer.write(gson.toJson(obj1));

            } else if (result.equals("session id wrong")) {
                JsonObject obj1 = new JsonObject();
                obj1.addProperty("statues", 500);
                obj1.addProperty("message", "internal error");
                GsonBuilder builder = new GsonBuilder();
                Gson gson = builder.create();
                writer.write(gson.toJson(obj1));
            } else{
                JsonObject obj1 = new JsonObject();
                obj1.addProperty("statues", 401);
                obj1.addProperty("message", "Username or Password wrong");
                GsonBuilder builder = new GsonBuilder();
                Gson gson = builder.create();
                writer.write(gson.toJson(obj1));
            }
        }
        writer.flush();
    }



    public void destroy() {
    }
}