import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;

class TOTPsample{
	public static void main(String[] argv) throws NoSuchAlgorithmException{
		TOTP totp = new TOTP();

		Date date = new Date();
		int tc = (int)(date.getTime() / (30*1000));
		for (int delay = 0; delay <= 2; delay++) {
			String token = totp.getToken(tc - delay); // 發起連線的那方傳送此token作為辨識
			System.out.println(token);

			System.out.println(totp.checkToken(token)); // 接收方呼叫此function檢驗是否為連線請求
		}
	}
}

class TOTP{
	String secret = "The Republic of China, founded on the Three Principles of the People, shall be a democratic republic of the people, to be governed by the people and for the people.";
	int acceptDelay = 1;
	MessageDigest digest;
	public TOTP() throws NoSuchAlgorithmException{
		this.digest = MessageDigest.getInstance("SHA-256");
	}

	boolean checkToken(String token) throws NoSuchAlgorithmException{
		Date date = new Date();
		int tc = (int)(date.getTime() / (30*1000));
		for (int delay = 0; delay <= acceptDelay; delay++) {
			String token2 = this.getToken(tc - delay);
			if (token.equals(token2)) {
				return true;
			}
		}
		return false;
	}
	String getToken() throws NoSuchAlgorithmException{
		Date date = new Date();
		int tc = (int)(date.getTime() / (30*1000));
		return this.getToken(tc);
	}
	String getToken(int tc) throws NoSuchAlgorithmException{
		String data = secret + Integer.toString(tc);

		byte[] hash = this.digest.digest(data.getBytes(StandardCharsets.UTF_8));
		StringBuffer strbuf = new StringBuffer();
		for (byte ch : hash) strbuf.append(Integer.toString((ch & 0xff) + 0x100, 16).substring(1));

		String res = strbuf.toString();
		return res;
	}
}
