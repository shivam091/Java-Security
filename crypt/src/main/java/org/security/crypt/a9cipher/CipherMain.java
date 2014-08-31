package org.security.crypt.a9cipher;

import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Main class to implement algorithms.
 * 
 * @author shivam
 *
 */
public class CipherMain {

	public static void main(String[] args) {
		@SuppressWarnings("resource")
		Scanner in = new Scanner(System.in);
		System.out.print("Enter 16-digit hex plaintext: ");
		String desPlainText = in.nextLine().toLowerCase();
		System.out.print("Enter 16-digit hex key: ");
		String desKey = in.nextLine().toLowerCase();

		boolean found = false;
		Pattern hexPattern = Pattern.compile("[^0-9a-f]");
		Matcher desPTMatcher = hexPattern.matcher(desPlainText);
		Matcher desKMatcher = hexPattern.matcher(desKey);
		while (desPTMatcher.find())
			found = true;
		while (desKMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {
			if (desPlainText.length() != 16)
				System.out.println("Plain text must be 16 digits");
			else if (desKey.length() != 16)
				System.out.println("Key must be 16 digits");
			else {
				byte[] bytePlainText = new byte[8];
				byte[] byteKey = new byte[8];
				for (int i = 0; i < 16; i += 2) {
					bytePlainText[i / 2] = (byte) ((Character.digit(
							desPlainText.charAt(i), 16) << 4) + Character
							.digit(desPlainText.charAt(i + 1), 16));
					byteKey[i / 2] = (byte) ((Character.digit(desKey.charAt(i),
							16) << 4) + Character.digit(desKey.charAt(i + 1),
							16));
				}
				try {
					DES newDES = new DES(byteKey);
					byte[] CTBytes = newDES.encrypt(bytePlainText);
					byte[] PTBytes = newDES.decrypt(CTBytes);

					String CTString = "";
					String PTString = "";
					for (int i = 0; i < 8; i++) {
						CTString += Integer.toString(
								(CTBytes[i] & 0xff) + 0x100, 16).substring(1);
						PTString += Integer.toString(
								(PTBytes[i] & 0xff) + 0x100, 16).substring(1);
					}

					System.out.println("Plaintext:  " + desPlainText);
					System.out.println("Key:        " + desKey);
					System.out.println("Ciphertext: " + CTString);
					System.out.println("Backtext:   " + PTString);

				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}

		System.out.println("Enter 32-digit hex plaintext: ");
		String rdPlainText = in.nextLine().toLowerCase();
		System.out.println("Enter 32-digit hex key: ");
		String rdKey = in.nextLine().toLowerCase();
		// String rdPlainText = "0123456789abcdeffedcba9876543210";
		// String rdKey = "0f1571c947d9e8590cb7add6af7f6798";
		found = false;
		Matcher rdPTMatcher = hexPattern.matcher(rdPlainText);
		Matcher rdKMatcher = hexPattern.matcher(rdKey);
		while (rdPTMatcher.find())
			found = true;
		while (rdKMatcher.find())
			found = true;
		if (found) {
			System.out.println("Plaintext and key must be hex encoded");
		} else {
			if (rdPlainText.length() != 32)
				System.out.println("Plain text must be 32 digits");
			else if (rdKey.length() != 32)
				System.out.println("Key must be 32 digits");
			else {
				int[] intPT = new int[16];
				int[] intK = new int[16];
				for (int i = 0; i < 32; i += 2) {
					intPT[i / 2] = (Character.digit(rdPlainText.charAt(i), 16) << 4)
							+ Character.digit(rdPlainText.charAt(i + 1), 16);
					intK[i / 2] = (Character.digit(rdKey.charAt(i), 16) << 4)
							+ Character.digit(rdKey.charAt(i + 1), 16);
				}
				try {
					Rijndael rd = new Rijndael(intK);
					int[] CTBytes = rd.encrypt(intPT);
					int[] PTBytes = rd.decrypt(CTBytes);

					String CTString = "";
					String PTString = "";
					for (int i = 0; i < 16; i++) {
						CTString += Integer.toString(
								(CTBytes[i] & 0xff) + 0x100, 16).substring(1);
						PTString += Integer.toString(
								(PTBytes[i] & 0xff) + 0x100, 16).substring(1);
					}

					System.out.println("Plaintext:  " + rdPlainText);
					System.out.println("Key:        " + rdKey);
					System.out.println("Ciphertext: " + CTString);
					System.out.println("Backtext:   " + PTString);
				} catch (Exception e) {
					System.out.println(e);
				}
			}
		}
	}

}
