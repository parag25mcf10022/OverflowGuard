import java.io.*;

public class PayloadLoader {
	// OBFUSCATION: The vulnerability isn't in what the code DOES, 
	// but in the TRUST it places in the ObjectInputStream.
	// Vulnerability: CRITICAL (CWE-502)
	public void loadSettings(byte[] data) {
		try {
			ByteArrayInputStream bis = new ByteArrayInputStream(data);
			// SpotBugs will flag this as DESERIALIZATION_VULNERABILITY
			ObjectInputStream ois = new ObjectInputStream(bis);
			
			System.out.println("[*] Reconstituting system object...");
			Object obj = ois.readObject(); 
			ois.close();
		} catch (Exception e) {
			System.out.println("[-] Error during load.");
		}
	}
	
	public static void main(String[] args) {
		PayloadLoader loader = new PayloadLoader();
		loader.loadSettings(new byte[]{0, 1, 2, 3}); // Dummy data
	}
}
