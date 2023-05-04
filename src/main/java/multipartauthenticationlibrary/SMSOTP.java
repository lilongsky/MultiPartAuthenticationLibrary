package multipartauthenticationlibrary;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;

public class SMSOTP {
    public static String sendOTP(String otp, String userEmailAddress,
                                 String mailSever, int port, String senderAddress, String senderPsw){

        try{
            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.ssl.protocols", "TLSv1.2");
            props.put("mail.smtp.host", mailSever);
            props.put("mail.smtp.port", port);

            Session session = Session.getInstance(props, new Authenticator() {
                @Override
                public PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(senderAddress, senderPsw);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderAddress));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(userEmailAddress));
            message.setSubject("SMS OTP Verification");
            message.setText("Your SMS OTP is " + otp);
            Transport.send(message);
            return "true";
        }catch (Exception e){
            return "error";
        }
    }

    public static String verifyOTP(String cCode, String sCode){

        if ((cCode == null)||(cCode.equals(""))) {
            return "empty Code";
        }
        if (sCode == null) {
            return "no Code Sent";
        }
        if (cCode.equals(sCode)) {
            return "true";
        } else {
            return "Wrong Code";
        }
    }
}
