import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.util.Arrays;

public class BeastAttack
{

    public static void main(String[] args) throws Exception
    {
	
	//-----------------------------------------------------------
	//  Demonstrate predict the IV
	// -----------------------------------------------------------
	byte[] ciphertext=new byte[1024];
	String[] timeArray = new String[16];
	String a = "00";
	String b = "00";
	int step = 0;
	for(int t =0;t<100;t++){
	    int length_2=callEncrypt(null, 0, ciphertext);
	    System.out.print("Real: ");
	    for(int k=0; k<8; k++){
		System.out.print(String.format("%02x ", ciphertext[k]));
		}
	     System.out.println("");
	    // Switch
	    b=a;
	    a= String.format("%02x", ciphertext[7]);
	    step = calStep(a,b);
	    
	    System.out.println("");
	    System.out.print("Pred: ");
	    for(int k=0; k<7; k++){
	       System.out.print(String.format("%02x ", ciphertext[k]));
	    }
	    System.out.println(String.format("%02x ", (byte)((int)ciphertext[7]+step)));  
	}


	
	// -----------------------------------------------------------
	//  Find the length of the plaintext
	// -----------------------------------------------------------
	byte[] prefix;
	int start = 0;
	int changePoint = 0;
	int lengthOfPlaintext=0;
	loop1
	for (int i = 0;i<9;i++){
	    prefix = generateZerosByteArray(i);
	    int length_3=callEncrypt(prefix, prefix.length, ciphertext);
	    System.out.println("-------------------------------------------------");
	    System.out.println("Prefix length = "+String.valueOf(i));
	    System.out.println("The length of ciphertext is "+String.valueOf(length_3));
	    if (i==0) {
		start = length_3;
	    }else{
		if(start!=length_3) {
		    changePoint = i-1;
		    lengthOfPlaintext = start-8-changePoint;
		    break loop1;
		}
	    }
	}
	System.out.println("-------------------------------------------------");
	System.out.println("The length of ciphertext changes when prefix length is "+String.valueOf(changePoint+1));
	System.out.println("Therefore, the length of Plaintext is "+
			   String.valueOf(start)+" - 8 - "+String.valueOf(changePoint+1)+" +1 = "
			   +String.valueOf(lengthOfPlaintext));
	
	
      	// -----------------------------------------------------------
	//  Decrypt the First 8 bytes
	// -----------------------------------------------------------
	//byte[] ciphertext=new byte[1024]; // will be plenty big enough
	int length=callEncrypt(null, 0, ciphertext);
	byte[] answer = new byte[length]; // Store the decryption
	byte[] r_guess; // The predicted message: r||(0~255)
	byte[] P_guess; // P = IV^IV_pred^r_guess
	byte[] C_guess; // E(IV_real)
	byte[] IV_real; // The real IV
	byte[] IV_pred; // The predicted IV
	byte temp = 0;
	step = 8;
	System.out.println("\nDecimal\tASCII");


	
	//------------------------------------------------------------
	// Guess the first 8 bytes
	//------------------------------------------------------------	
	for(int i = 0; i<8; i++){
	    byte[] zero_and_ans; // Array of prefixed 0s and known chars
	    byte[] zeros = generateZerosByteArray(7-i); // Generating array of i 0s
	    
	    if(i>0){
	        zero_and_ans = concatenateByteArrays(zeros,Arrays.copyOfRange(answer,0,i));
	    }else{
	        zero_and_ans = zeros;
	    }

	    //
	    int length_i0s=callEncrypt(zeros, zeros.length, ciphertext);
	    byte[] C0 = Arrays.copyOfRange(ciphertext,0,8); // The IV
	    byte[] C1 = Arrays.copyOfRange(ciphertext,8,16);// The first 8-byte ciphertext
	    IV_pred = C0;
	    
	    label1:
	    for(int k = 0; k < 50; k++){
		// Only guess "space,a-z,A-Z".But range 0-255 should be applied.
		for (int guess = 32; guess<123;guess++){
		    byte[] b_guess = new byte[]{(byte)guess};
		    r_guess = concatenateByteArrays(zero_and_ans,b_guess); // known plaintext+guess
		    P_guess = xorByteArray(xorByteArray(C0,r_guess),IV_pred);
		    callEncrypt(P_guess, P_guess.length, ciphertext);
		    IV_real = Arrays.copyOfRange(ciphertext,0,8);

		    if (Arrays.equals(IV_real,IV_pred)){
			C_guess = Arrays.copyOfRange(ciphertext,8,16);
			if (Arrays.equals(C_guess,C1)){
			    System.out.print(guess);
			    answer[i] = (byte)guess;
			    System.out.println("\t  "+(char)guess);
			    break label1;
			}
		    }
		    // Find step
		    b=a;
		    a = String.format("%02x", ciphertext[7]);
		    step = calStep(a,b);
		    // Predict the next IV  
		    IV_real[7]= (byte)((int)IV_real[7]+step);
		    IV_pred = IV_real;
		}
	    }

	    
	}// end of decryption


	//------------------------------------------------------------
	//  Decrpyt the remaining ciphertext
	//------------------------------------------------------------
	mainloop:
	for (int block = 2;block<length/8;block++){
	    for (int i = 0; i<8; i++){
		if(lengthOfPlaintext==((block-1)*8+i)) break mainloop; //Break if all plaintexts are obtained
	        byte[] zeros = generateZerosByteArray(7-i);
		byte[] knownAns = Arrays.copyOfRange(answer,(block-2)*8+1+i,(block-2)*8+8+i);
	        callEncrypt(zeros, zeros.length, ciphertext);
		
		byte[] C0 = Arrays.copyOfRange(ciphertext,(block-1)*8,block*8); // The IV
		byte[] C1 = Arrays.copyOfRange(ciphertext,block*8,(block+1)*8);// The target 8-byte ciphertext
	        IV_pred = C0;

		label1:
		for (int k = 0;k<50;k++){
		    for (int guess = 32; guess<123; guess++){
			byte[] b_guess = new byte[]{(byte)guess};
			r_guess = concatenateByteArrays(knownAns,b_guess);
			P_guess = xorByteArray(xorByteArray(C0,r_guess),IV_pred);
			callEncrypt(P_guess, P_guess.length, ciphertext);
			IV_real = Arrays.copyOfRange(ciphertext,0,8);

			if (Arrays.equals(IV_real,IV_pred)){
			    C_guess = Arrays.copyOfRange(ciphertext,8,16);
			    if (Arrays.equals(C_guess,C1)){
				System.out.print(guess);
				answer[(block-1)*8+i] = (byte)guess;
				System.out.println("\t  "+(char)guess);
				break label1;
			    }
			}
			// Calculate step
			b=a;
		        a = String.format("%02x", ciphertext[7]);
		        step = calStep(a,b);
			// Predict the IV
		        IV_real[7] = (byte)((int)IV_real[7]+step);
			IV_pred = IV_real;
		    }
		}
	    }

	}
	String result = new String(answer, "ASCII");
	System.out.println(result);
    }
    


    // a helper method to call the external programme "encrypt" in the current directory
    // the parameters are the plaintext, length of plaintext, and ciphertext; returns length of ciphertext
    static int callEncrypt(byte[] prefix, int prefix_len, byte[] ciphertext) throws IOException
    {
	HexBinaryAdapter adapter = new HexBinaryAdapter();
	Process process;
	
	// run the external process (don't bother to catch exceptions)
	if(prefix != null)
	{
	    // turn prefix byte array into hex string
	    byte[] p=Arrays.copyOfRange(prefix, 0, prefix_len);
	    String PString=adapter.marshal(p);
	    process = Runtime.getRuntime().exec("./encrypt "+PString);
	}
	else
	{
	    process = Runtime.getRuntime().exec("./encrypt");
	}

	// process the resulting hex string
	String CString = (new BufferedReader(new InputStreamReader(process.getInputStream()))).readLine();
	byte[] c=adapter.unmarshal(CString);
	System.arraycopy(c, 0, ciphertext, 0, c.length); 
	return(c.length);
    }

    // XOR two byte array, and return the result.
    public static byte[] xorByteArray(byte[] byteArray_1, byte[] byteArray_2){
	byte[] byteArray_output = new byte[byteArray_1.length];
	for (int i = 0; i<byteArray_1.length;i++){
	    byteArray_output[i] = (byte)(((int)byteArray_1[i])^ ((int)byteArray_2[i]));
	}
	return byteArray_output;
		
    }

    // Print the byteArray in HEX string
    public static String[] printByteArray(byte[] byteArray){
	String [] result = new String[byteArray.length];
	for (int i = 0; i<byteArray.length;i++){
	    result[i]= String.format("%02x ", byteArray[i]);
	    System.out.print(result[i]);
	}
	System.out.println("");
	return result;
    }
    
    // Generate an array of 0s
    public static byte[] generateZerosByteArray(int num){
	byte[] result = new byte[num];
	for (int i = 0; i < num; i++){
	    result[i] = (byte)0;
	}
	return result;
    }

    // Concatenate two byte arrays
    public static byte[] concatenateByteArrays(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length]; 
    System.arraycopy(a, 0, result, 0, a.length); 
    System.arraycopy(b, 0, result, a.length, b.length); 
    return result;
    }

    // Calculate the step
    public static int calStep(String A, String B){
	int a = Integer.parseInt(A,16);
	int b = Integer.parseInt(B,16);
	return Math.abs(b-a);	
    }

}
