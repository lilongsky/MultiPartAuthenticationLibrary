package com.example.multipartauthenticationApplication;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import multipartauthenticationlibrary.*;

import jakarta.servlet.http.*;
import jakarta.servlet.annotation.*;

import java.io.IOException;
import java.io.PrintWriter;


@WebServlet(name = "RegisterServlet",value = "/register")
public class RegisterServlet extends HttpServlet{

    String MAIL_SEVER_ADDRESS = secret.MAIL_SEVER_ADDRESS;
    String MAIL_SENDER_ADDRESS = secret.MAIL_SENDER_ADDRESS;
    String MAIL_SEVER_PSW = secret.MAIL_SEVER_PSW;
    int MAIL_SEVER_PORT = secret.MAIL_SEVER_PORT;

    String issuer = "Test";

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException{
        PrintWriter writer = response.getWriter();
        HttpSession session = request.getSession();
        session.setMaxInactiveInterval(1800);

        JsonObject obj = new JsonObject();
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();

        response.setContentType("application/json");

        String stepCode = request.getParameter("stepCode");

        if (stepCode.equals("0")){

            String UsrName = request.getParameter("UserName");
            String UsrPsw = request.getParameter("UserPsw");

            if (database.UserandPsw.containsKey(UsrName)){

                obj.addProperty("statue","-1");
                obj.addProperty("message","same username find");
            }else {

                database.UserandPsw.put(UsrName,UsrPsw);
                obj.addProperty("statue",200);
                obj.addProperty("message","");
                database.UserandAuthType.put(UsrName,7);
                session.setAttribute("UserName",UsrName);
            }
        }
        if (stepCode.equals("1")){

            String typeCode = request.getParameter("typeCode");
            String UsrName = (String) session.getAttribute("UserName");

            if (typeCode.equals("0")){
                String token = TOTP.TOTPTokenGenerator();
                session.setAttribute("TOTPToken",token);
                String TOTPUrl = TOTP.TOTPUrlGenerator(UsrName,issuer,token);
                obj.addProperty("statue",200);
                obj.addProperty("TOTPTokenUrl",TOTPUrl);
                obj.addProperty("TOTPToken",token);

            } else if (typeCode.equals("1")){

                String userPhone = request.getParameter("PhoneNumber");
                String otp = RegisterLib.SMSOTPSender(userPhone,
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);

                if (otp != null) {
                    session.setAttribute("SMSOTP", otp);
                    session.setAttribute("PhoneNumber",userPhone);

                    obj.addProperty("statue", 200);

                }else {
                    obj.addProperty("statues", 500);
                    obj.addProperty("message", "internal error");
                }
            }else if (typeCode.equals("2")){

                String userEmailAddress = request.getParameter("Email");
                String otp = RegisterLib.EmailOTPSender(userEmailAddress,
                        MAIL_SEVER_ADDRESS,MAIL_SEVER_PORT,MAIL_SENDER_ADDRESS,MAIL_SEVER_PSW);

                if (otp != null) {
                    session.setAttribute("EmailOTP", otp);
                    session.setAttribute("EmailAddress",userEmailAddress);

                    obj.addProperty("statue", 200);

                }else {
                    obj.addProperty("statues", 500);
                    obj.addProperty("message", "internal error");
                }
            } else if (typeCode.equals("3")) {

                String[] BackupCode = BackUpOTP.GenerateOTP(8,8);

                database.UserandBackUpOTP.put(UsrName,BackupCode)
                ;
                obj.addProperty("statue", 200);
                obj.add("BackUpCodeArray",gson.toJsonTree(BackupCode).getAsJsonArray());

            } else {
                obj.addProperty("statues", 500);
                obj.addProperty("message", "internal error");
            }
        }
        writer.write(gson.toJson(obj));
        writer.flush();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException{
        PrintWriter writer = response.getWriter();
        HttpSession session = request.getSession();
        JsonObject obj = new JsonObject();
        GsonBuilder builder = new GsonBuilder();
        Gson gson = builder.create();

        response.setContentType("application/json");

        String stepCode = request.getParameter("stepCode");

        String UsrName = (String) session.getAttribute("UserName");

        if (stepCode.equals("2")){
            String sSMSOTP = (String) session.getAttribute("SMSOTP");
            String sEmailOTP = (String) session.getAttribute("EmailOTP");
            String TOTPToken = (String) session.getAttribute("TOTPToken");

            String cSMSOTP = request.getParameter("SMSOTP");
            String cEmailOTP = request.getParameter("EmailOTP");
            String cTOTPCode = request.getParameter("TOTP");

            boolean checkResult = true;

            if (TOTPToken != null){
                String result0 = RegisterLib.TOTPVerifier(cTOTPCode,TOTPToken);

                if (!(result0.equals("true"))){

                    obj.addProperty("statue","-1");
                    obj.addProperty("message0",result0);

                    checkResult = false;
                }else {

                    int oldAuthType = database.UserandAuthType.get(UsrName);
                    int newAuthType = 7;
                    if (oldAuthType == 7){// no 2FA before
                        newAuthType = 0;//0 is TOTP
                    } else if ((oldAuthType < 3)&&(oldAuthType != 0)){//one 2FA before
                        newAuthType = 2+0+oldAuthType;// add TOTP
                    }else if ((oldAuthType <6)
                            &&(oldAuthType != 3)&&(oldAuthType != 4)){//2 2FA before
                        newAuthType = 1+0+oldAuthType;// add TOTP
                    }
                    database.UserandAuthType.replace(UsrName,newAuthType);
                    database.UsrTOTPToken.put(UsrName,TOTPToken);
                    session.removeAttribute("TOTPToken");
                }
            }

            if (sSMSOTP != null){
                String result1 = RegisterLib.SMSOTPVerifier(cSMSOTP,sSMSOTP);
                if (!(result1.equals("true"))){
                    obj.addProperty("statue","-1");
                    obj.addProperty("message1",result1);
                    checkResult = false;
                }else {
                    int oldAuthType = database.UserandAuthType.get(UsrName);
                    int newAuthType = 7;
                    if (oldAuthType == 7){// no 2FA before
                        newAuthType = 1;//add SMS
                    } else if ((oldAuthType < 3)&&(oldAuthType != 1)) {//one 2FA before
                        newAuthType = 2+1+oldAuthType;//add SMS
                    }else if ((oldAuthType <6)
                            &&(oldAuthType != 3)&&(oldAuthType != 5)){//2 2FA before
                        newAuthType = 1+1+oldAuthType;//add SMS
                    }
                    database.UserandAuthType.replace(UsrName,newAuthType);

                    String userPhone = (String) session.getAttribute("PhoneNumber");
                    database.UserandPhone.put(UsrName,userPhone);

                    session.removeAttribute("PhoneNumber");
                    session.removeAttribute("SMSOTP");
                }
            }

            if (sEmailOTP != null){
                String result2 = RegisterLib.EmailOTPVerifier(cEmailOTP,sEmailOTP);
                if (!(result2.equals("true"))){
                    obj.addProperty("statue","-1");
                    obj.addProperty("message2",result2);
                    checkResult = false;
                }else {
                    int oldAuthType = database.UserandAuthType.get(UsrName);
                    int newAuthType = 7;
                    if (oldAuthType == 7){
                        newAuthType = 2;
                    } else if ((oldAuthType < 3)&&(oldAuthType != 2)){
                        newAuthType = 2+2+oldAuthType;
                    }else if ((oldAuthType <6)
                            &&(oldAuthType != 4)&&(oldAuthType != 5)){
                        newAuthType = 1+2+oldAuthType;
                    }
                    database.UserandAuthType.replace(UsrName,newAuthType);
                    String userEmailAddress = (String) session.getAttribute("EmailAddress");
                    database.UserandEmail.put(UsrName,userEmailAddress);
                    session.removeAttribute("EmailAddress");
                    session.removeAttribute("EmailOTP");
                }
            }
            if (checkResult){
                obj.addProperty("statue",302);
                obj.addProperty("message3","Register success");
                obj.addProperty("location","./index.html");
            }
        }

        writer.write(gson.toJson(obj));
        writer.flush();
    }

}
