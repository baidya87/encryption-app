package com.baidya.digest;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Certificate {

	public static void main(String[] args) {
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
			certificateFactory.generateCertificate(new FileInputStream("certificates/ab.cer"));
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}
}
