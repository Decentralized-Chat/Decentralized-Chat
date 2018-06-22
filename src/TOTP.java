import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.charset.StandardCharsets;

class TOTP{
	private String secret = "";
	private int acceptDelay = 1;
	MessageDigest digest;
	public TOTP(String secret, int acceptDelay) throws NoSuchAlgorithmException{
		this.secret = secret;
		this.acceptDelay = acceptDelay;
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
