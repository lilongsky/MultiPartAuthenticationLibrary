package com.example.multipartauthenticationApplication;
import multipartauthenticationlibrary.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;


import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;

import java.io.IOException;
import java.io.PrintWriter;

@WebServlet(name = "LoginSecondServlet", value = "/login-second")
public class LoginSecondServlet extends HttpServlet {
    String MAIL_SEVER_ADDRESS = secret.MAIL_SEVER_ADDRESS;
    String MAIL_SENDER_ADDRESS = secret.MAIL_SENDER_ADDRESS;
    String MAIL_SEVER_PSW = secret.MAIL_SEVER_PSW;
    int MAIL_SEVER_PORT = secret.MAIL_SEVER_PORT;
    int AuthType = 0;
    String username;

    String userEmailAddress = secret.userEmailAddress;

    String EmailToken = "ORSXG5DUMVZXI===";
    int emailCounter = 0;
    String SMSToken = "ORSXG5DUMVZXIMJSGM2DKNQ=";
    int phoneCounter = 0;
    String TOTPToken = "GEZDGNBVGZ2GK43UORSXG5A";

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException{
        PrintWriter writer = response.getWriter();
        HttpSession session = request.getSession();
        JsonObject obj1 = new JsonObject();

        String isFirstAuthenticated = (String)session.getAttribute("isFirstAuthenticated");
        if ((isFirstAuthenticated != null)&&(isFirstAuthenticated.equals("true"))){
            String cAuthType = request.getParameter("AuthType");
            String AuthTypeCode = request.getParameter("AuthTypeCode");
            response.setContentType("application/json");
            if ((cAuthType != null)&&(cAuthType.equals("-1"))){
                username = (String) session.getAttribute("username");

                obj1.addProperty("AuthType", AuthType);
                obj1.addProperty("statues",200);
                obj1.addProperty("location","");
            }else if ((AuthTypeCode != null)&&(AuthTypeCode.equals("1"))){
                obj1.addProperty("statues",200);
                LoginLib.SMSOTPSender(username,userEmailAddress,SMSToken,phoneCounter,
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);
                phoneCounter++;
                obj1.addProperty("message","OTP sent");
            } else if ((AuthTypeCode != null)&&(AuthTypeCode.equals("2"))) {
                obj1.addProperty("statues",200);
                LoginLib.EmailOTPSender(username,userEmailAddress,EmailToken,emailCounter,
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);
                emailCounter++;
                obj1.addProperty("message","OTP sent");
            }
        }else {
            obj1.addProperty("AuthType", -1);
            obj1.addProperty("statues",302);
            obj1.addProperty("location","./index.html");
        }
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();
        writer.write(gson.toJson(obj1));
        writer.flush();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException{
        PrintWriter writer = response.getWriter();
        HttpSession session = request.getSession();
        JsonObject obj1 = new JsonObject();
        response.setContentType("application/json");
        username = (String) session.getAttribute("username");
        boolean checkResult = false;
        String result0,result1,result2;
        if ((AuthType/3)==0){
            switch (AuthType){
                case 0:
                    result0 = LoginLib.TOTPVerifier(request,TOTPToken);
                    if (result0.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                case 1:
                    result1 = LoginLib.SMSOTPVerifier(request,username);
                    if (result1.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                case 2:
                    result2 = LoginLib.EmailOTPVerifier(request,username);
                    if (result2.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                default:
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
            }
        } else if ((AuthType/3)==1) {
            switch (AuthType%3){
                case 0:
                    result0 = LoginLib.TOTPVerifier(request,TOTPToken);
                    result1 = LoginLib.SMSOTPVerifier(request,username);
                    if (result0.equals("true")&&
                            result1.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                case 1:
                    result0 = LoginLib.TOTPVerifier(request,TOTPToken);
                    result2 = LoginLib.EmailOTPVerifier(request,username);
                    if (result0.equals("true")&&
                            result2.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                case 2:
                    result1 = LoginLib.SMSOTPVerifier(request,username);
                    result2 = LoginLib.EmailOTPVerifier(request,username);
                    if (result1.equals("true") &&
                            result2.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        checkResult = true;
                    }
                default:
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
            }
        } else if (((AuthType/3) == 2)) {
            result0 = LoginLib.TOTPVerifier(request,TOTPToken);
            result1 = LoginLib.SMSOTPVerifier(request,username);
            result2 = LoginLib.EmailOTPVerifier(request,username);

            if (result0.equals("true")&&
                    result1.equals("true")&&
                    result2.equals("true")){
                obj1.addProperty("statues",302);
                obj1.addProperty("location","./userinfo.html");
                checkResult = true;
            }
        }else {
            obj1.addProperty("statues",500);
            obj1.addProperty("message","internal error");
        }

        if (checkResult){
            obj1.addProperty("statues",302);
            obj1.addProperty("message","2FA wrong");
        }
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();
        writer.write(gson.toJson(obj1));
        writer.flush();
    }

}
