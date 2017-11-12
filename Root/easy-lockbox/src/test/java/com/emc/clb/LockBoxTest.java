package com.emc.clb;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.junit.Assert;
import org.junit.Test;


public class LockBoxTest {
	
	@Test
	public void test_base64_1() throws IOException {
		String s = LockBox.base64Encode("abc".getBytes());
		Assert.assertNotEquals("abc", s);
		String t = new String(LockBox.base64Decode(s));
		Assert.assertEquals("abc", t);
	}

	@Test
	public void test_encryption_1() throws IOException, GeneralSecurityException {
		LockBox lb = new LockBox(null, null);
		String s = lb.encrypt("abc.def");
		Assert.assertNotEquals("abc.def", s);
		Assert.assertEquals("abc.def", lb.decrypt(s));
	}
	
	@Test
	public void test_encryption_2() throws IOException, GeneralSecurityException {
		LockBox lb = new LockBox(null, null);
		String s = lb.encrypt("abc.def");
		Assert.assertNotEquals("abc.def", s);
		Assert.assertEquals("abc.def", lb.decrypt(s));
	}
	
	@Test
	public void test_encryption_3() throws IOException, GeneralSecurityException {
		LockBox lb = new LockBox(null, null);
		String s = lb.encrypt("abc.def");
		Assert.assertNotEquals("abc.def", s);
		
		lb = new LockBox(null, null);
		Assert.assertEquals("abc.def", lb.decrypt(s));
	}

	@Test
	public void test_encryption_4() throws IOException, GeneralSecurityException {
		LockBox lb = new LockBox(null, null);
		System.out.println(lb.retrieveItemAsText("D2Method.passphrase"));
		
	}
}
