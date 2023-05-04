package com.example.multipartauthenticationApplication;
import multipartauthenticationlibrary.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;


import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;


import java.io.IOException;
import java.io.PrintWriter;

import java.util.ArrayList;
import java.util.Base64;


@WebServlet(name = "LoginSecondServlet", value = "/login-second")
public class LoginSecondServlet extends HttpServlet {
    String MAIL_SEVER_ADDRESS = secret.MAIL_SEVER_ADDRESS;
    String MAIL_SENDER_ADDRESS = secret.MAIL_SENDER_ADDRESS;
    String MAIL_SEVER_PSW = secret.MAIL_SEVER_PSW;
    int MAIL_SEVER_PORT = secret.MAIL_SEVER_PORT;
    String username;


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException{
        PrintWriter writer = response.getWriter();
        HttpSession session = request.getSession();
        JsonObject obj1 = new JsonObject();
        response.setContentType("application/json");
        String isFirstAuthenticated = (String)session.getAttribute("isFirstAuthenticated");
        if ((isFirstAuthenticated != null)&&(isFirstAuthenticated.equals("true"))){
            String cAuthType = request.getParameter("AuthType");
            String AuthTypeCode = request.getParameter("AuthTypeCode");

            if ((cAuthType != null)&&(cAuthType.equals("-1"))){
                username = (String) session.getAttribute("username");

                obj1.addProperty("statues",200);
                obj1.addProperty("location","");

            }else if ((AuthTypeCode != null)&&(AuthTypeCode.equals("1"))){

                String otp = LoginLib.SMSOTPSender(database.UserandPhone.get(username),
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);

                if (otp != null){
                    database.UsrSMSOTPCode.put(username,otp);

                    obj1.addProperty("statues",200);
                    obj1.addProperty("message","OTP sent");
                }else {
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
                }
            } else if ((AuthTypeCode != null)&&(AuthTypeCode.equals("2"))) {

                String otp =  LoginLib.EmailOTPSender(database.UserandEmail.get(username),
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);
                if (otp != null){
                    database.UsrEmailOTPCode.put(username,otp);

                    obj1.addProperty("statues",200);
                    obj1.addProperty("message","OTP sent");
                }else {
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
                }

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
        boolean checkResult = true;
        String result0,result1,result2;
        int AuthType = database.UserandAuthType.get(username);
        String[] resultBackUpCode = LoginLib.BackUpCodeVerifier(request, database.UserandBackUpOTP.get(username));
        if (!resultBackUpCode[0].equals("empty Code")) {
            if (resultBackUpCode[0].equals("true")) {

                String[] BackUpCode = database.UserandBackUpOTP.get(username);
                ArrayList<String> tempList = new ArrayList<>();
                for (String i:BackUpCode){
                    if (!i.equals(resultBackUpCode[1])){
                        tempList.add(i);
                    }
                }
                String[] newBackUpCode = tempList.toArray(new String[0]);
                database.UserandBackUpOTP.remove(username);
                database.UserandBackUpOTP.put(username,newBackUpCode);

                session.setAttribute("Reset2FA",true);
            }else {
                checkResult = false;
            }
        } else if ((AuthType/3)==0){
            switch (AuthType){
                case 0:
                    result0 = LoginLib.TOTPVerifier(request,database.UsrTOTPToken.get(username));
                    if (!result0.equals("true")){
                        checkResult = false;
                    }
                    break;
                case 1:
                    result1 = LoginLib.SMSOTPVerifier(request,database.UsrSMSOTPCode.get(username));
                    if (result1.equals("true")){

                        database.UsrSMSOTPCode.remove(username);
                    }else {
                        checkResult = false;
                    }
                    break;
                case 2:
                    result2 = LoginLib.EmailOTPVerifier(request,database.UsrEmailOTPCode.get(username));
                    if (result2.equals("true")){

                        database.UsrEmailOTPCode.remove(username);
                    }else {
                        checkResult = false;
                    }
                    break;
                default:
                    checkResult = false;
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
                    break;
            }
        } else if ((AuthType/3)==1) {
            switch (AuthType%3){
                case 0:
                    result0 = LoginLib.TOTPVerifier(request,database.UsrTOTPToken.get(username));
                    result1 = LoginLib.SMSOTPVerifier(request,database.UsrSMSOTPCode.get(username));
                    if (result0.equals("true")&&
                            result1.equals("true")){


                        database.UsrSMSOTPCode.remove(username);
                    }else {
                        checkResult = false;
                    }
                    break;
                case 1:
                    result0 = LoginLib.TOTPVerifier(request,database.UsrTOTPToken.get(username));
                    result2 = LoginLib.EmailOTPVerifier(request,database.UsrEmailOTPCode.get(username));

                    if (result0.equals("true")&&
                            result2.equals("true")){
                        database.UsrEmailOTPCode.remove(username);
                    }else {
                        checkResult = false;
                    }
                    break;
                case 2:
                    result1 = LoginLib.SMSOTPVerifier(request,database.UsrSMSOTPCode.get(username));
                    result2 = LoginLib.EmailOTPVerifier(request,database.UsrEmailOTPCode.get(username));
                    if (result1.equals("true") &&
                            result2.equals("true")){
                        obj1.addProperty("statues",302);
                        obj1.addProperty("location","./userinfo.html");
                        database.UsrSMSOTPCode.remove(username);
                        database.UsrEmailOTPCode.remove(username);
                    }else {
                        checkResult = false;
                    }
                    break;
                default:
                    obj1.addProperty("statues",500);
                    obj1.addProperty("message","internal error");
            }
        } else if (((AuthType/3) == 2)) {
            switch (AuthType % 3) {
                case 0:
                    result0 = LoginLib.TOTPVerifier(request, database.UsrTOTPToken.get(username));
                    result1 = LoginLib.SMSOTPVerifier(request, database.UsrSMSOTPCode.get(username));
                    result2 = LoginLib.EmailOTPVerifier(request, database.UsrEmailOTPCode.get(username));

                    if (result0.equals("true") &&
                            result1.equals("true") &&
                            result2.equals("true")) {
                        database.UsrSMSOTPCode.remove(username);
                        database.UsrEmailOTPCode.remove(username);

                    }else {
                        checkResult = false;
                    }
                    break;
                case 1:
                    break;
            }
        }else {
            obj1.addProperty("statues",500);
            obj1.addProperty("message"," internal error");
        }

        if (!checkResult){
            obj1.addProperty("statues",401);
            obj1.addProperty("message","2FA wrong");
        }
        if (checkResult){
            String sID = Base64.getEncoder().encodeToString(SafeToolBox.SafetyRandomBytesGenerator(56));
            Cookie cookie = new Cookie("sID", sID);
            cookie.setMaxAge(60 * 60 * 24);
            cookie.setPath("/");
            cookie.setHttpOnly(true);
            //cookie.setSecure(true);
            response.addCookie(cookie);

            database.UserandCookie.putIfAbsent(username,sID);
            //Sid should write in to database to compare in userinfo,
            // in demo, no database,so I just use fix String.

            obj1.addProperty("statues",302);
            obj1.addProperty("location","./userinfo.html");
        }

        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();
        writer.write(gson.toJson(obj1));
        writer.flush();
    }

}
