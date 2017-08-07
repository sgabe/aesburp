package burp;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.awt.*;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.JLabel;
import javax.swing.SwingConstants;
import javax.swing.JTextArea;
import javax.swing.JComboBox;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JButton;
import javax.swing.JScrollPane;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.beans.PropertyChangeListener;
import java.beans.PropertyChangeEvent;

public class BurpExtender implements IBurpExtender, IScannerInsertionPointProvider, ITab, IMessageEditorTabFactory, IProxyListener, IHttpListener {
    
	// IExtensionHelpers helpers;
	public IExtensionHelpers helpers;
    public IBurpExtenderCallbacks callbacks;

    // GUI Components
    private JPanel panel;
    
    public final String TAB_NAME = "AES Config";
    private JTextField parameterAESkey;
    private JTextField parameterAESIV;
    private JLabel lblDescription;
    private JComboBox comboAESMode;
    private JLabel lbl3;
    private JCheckBox chckbxNewCheckBox;
    private JCheckBox chckbxEnableListeners;
    private JPanel panel_1;
    private JButton btnNewButton;
    private JTextArea textAreaPlaintext;
    private JTextArea textAreaCiphertext;
    private JScrollPane plainTextScroll;
    private JScrollPane cipherTextScroll;
    private JButton btnNewButton_1;
    private JLabel lblPlaintext;
    private JLabel lblCiphertext;

    public IntruderPayloadProcessor payloadEncryptor;
    public IntruderPayloadProcessor payloadDecryptor;
    
    public Boolean isURLEncoded;
    
    private JLabel lbl4;
    private JComboBox comboEncoding;
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    	this.callbacks = callbacks;
    	
    	// obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("AES Crypto v1.3");
      
        // Register payload encoders
        payloadEncryptor = new IntruderPayloadProcessor(this, 1);
        callbacks.registerIntruderPayloadProcessor(payloadEncryptor);
        
        payloadDecryptor = new IntruderPayloadProcessor(this, 0);
        callbacks.registerIntruderPayloadProcessor(payloadDecryptor);
        
        // register ourselves as a scanner insertion point provider
        callbacks.registerScannerInsertionPointProvider(this);
        
        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        // register ourselves as a Proxy listener
        callbacks.registerProxyListener(this);

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        isURLEncoded = false;
        
        // Create UI
        this.addMenuTab();
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // create a new instance of the AES editor tab
        return new AESTab(controller, editable);
    }

    //
    // class implementing IMessageEditorTab
    //

    class AESTab implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;
        private int currentBodyOffset;

        public AESTab(IMessageEditorController controller, boolean editable) {
            this.editable = editable;

            // create an instance of Burp's text editor, to display the decrypted body
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption() {
            return "Decrypted";
        }

        @Override
        public Component getUiComponent() {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            String body = "";
            byte[] bodyArray = content;
            int bodyOffset = 0;

            if (isRequest) {
                bodyOffset = helpers.analyzeRequest(content).getBodyOffset();
                bodyArray = Arrays.copyOfRange(content, bodyOffset, content.length);
                body = helpers.bytesToString(bodyArray).replaceAll("\r", "").replaceAll("\n", "");
            } else {
                bodyOffset = helpers.analyzeResponse(content).getBodyOffset();
                bodyArray = Arrays.copyOfRange(content, bodyOffset, content.length);
                body = helpers.bytesToString(bodyArray);
            }

            try {
                decrypt(body);
                return true;
            } catch(Exception e) {
                return false;
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            String body = "";
            byte[] bodyArray = content;
            int bodyOffset = 0;

            if (content == null) {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            } else {

                if (isRequest) {
                    bodyOffset = helpers.analyzeRequest(content).getBodyOffset();
                    bodyArray = Arrays.copyOfRange(content, bodyOffset, content.length);
                    body = helpers.bytesToString(bodyArray).replaceAll("\r", "").replaceAll("\n", "");
                } else {
                    bodyOffset = helpers.analyzeResponse(content).getBodyOffset();
                    bodyArray = Arrays.copyOfRange(content, bodyOffset, content.length);
                    body = helpers.bytesToString(bodyArray);
                }

                try {
                    // decrypt the body
                    txtInput.setText(helpers.stringToBytes(decrypt(body)));
                    txtInput.setEditable(editable);
                } catch(Exception e) {
                }

            }

            // remember the displayed content
            currentMessage = content;
            currentBodyOffset = bodyOffset;
        }

        @Override
        public byte[] getMessage() {
            // determine whether the user modified the decrypted body
            if (txtInput.isTextModified()) {
                try {
                    // encrypt the new message body
                    String plainText = helpers.bytesToString(txtInput.getText());
                    String cipherText = encrypt(plainText);
                    byte[] newBody = helpers.stringToBytes(cipherText);

                    // replace the original message body with the new one
                    byte[] newMessage = new byte[currentBodyOffset + newBody.length];
                    System.arraycopy(currentMessage, 0, newMessage, 0, currentBodyOffset);
                    System.arraycopy(newBody, 0, newMessage, currentBodyOffset, newBody.length);

                    return newMessage;
                } catch(Exception e) {
                }
            }
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData() {
            return txtInput.getSelectedText();
        }
    }

    /**
     * @wbp.parser.entryPoint
     * 
     * This code was built using Eclipse's WindowBuilder
     */
    public void buildUI() {
    	panel = new JPanel();
    	GridBagLayout gbl_panel = new GridBagLayout();
    	gbl_panel.columnWidths = new int[]{197, 400, 0};
        gbl_panel.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0};
    	gbl_panel.columnWeights = new double[]{1.0, 1.0, Double.MIN_VALUE};
        gbl_panel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel.setLayout(gbl_panel);

        lblDescription = new JLabel("<html><b>BURP AES Manipulation functions v1.3</b>\r\n<br>\r\n<br>\r\ntwitter: twitter.com/lgrangeia\r\n<br>\r\ngithub: github.com/lgrangeia\r\n<br>\r\n<br>\r\nAES key can be 128, 192 or 256 bits, but you need to install Java Cryptography Extension (JCE) Unlimited Strength for 256 bit keys.<br>\r\nThis extension registers the following:\r\n<ul>\r\n  <li>AES Encrypt / Decrypt Payload Encoder</li>\r\n  <li>Scanner Insertion Point Provider: attempts to insert payloads inside encrypted insertion points</li>\r\n  <li>Custom editor tab: attempts to decrypt the message body</li>\r\n  <li>Proxy and HTTP listeners: allows to transparently decrypt / encrypt requests and responses (useful for scanning when the message body is encrypted)</li>\r\n</ul>\r\n\r\n</html>");
    	lblDescription.setHorizontalAlignment(SwingConstants.LEFT);
    	lblDescription.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_lblDescription = new GridBagConstraints();
    	gbc_lblDescription.fill = GridBagConstraints.HORIZONTAL;
    	gbc_lblDescription.insets = new Insets(20, 20, 20, 20);
    	gbc_lblDescription.gridx = 1;
    	gbc_lblDescription.gridy = 0;
    	panel.add(lblDescription, gbc_lblDescription);
    	
    	JLabel lbl1 = new JLabel("AES key in hex format:");
    	lbl1.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl1 = new GridBagConstraints();
    	gbc_lbl1.anchor = GridBagConstraints.EAST;
    	gbc_lbl1.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl1.gridx = 0;
    	gbc_lbl1.gridy = 1;
    	panel.add(lbl1, gbc_lbl1);
    	
    	parameterAESkey = new JTextField();
    	parameterAESkey.setText("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    	GridBagConstraints gbc_parameterAESkey = new GridBagConstraints();
    	gbc_parameterAESkey.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterAESkey.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterAESkey.gridx = 1;
    	gbc_parameterAESkey.gridy = 1;
    	panel.add(parameterAESkey, gbc_parameterAESkey);
    	parameterAESkey.setColumns(10);
    	
    	JLabel lbl2 = new JLabel("IV in hex format:");
    	lbl2.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl2 = new GridBagConstraints();
    	gbc_lbl2.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl2.anchor = GridBagConstraints.EAST;
    	gbc_lbl2.gridx = 0;
    	gbc_lbl2.gridy = 2;
    	panel.add(lbl2, gbc_lbl2);
    	
    	parameterAESIV = new JTextField();
    	parameterAESIV.setText("abcdef1234567890abcdef1234567890");
    	parameterAESIV.setColumns(10);
    	GridBagConstraints gbc_parameterAESIV = new GridBagConstraints();
    	gbc_parameterAESIV.insets = new Insets(0, 0, 5, 0);
    	gbc_parameterAESIV.fill = GridBagConstraints.HORIZONTAL;
    	gbc_parameterAESIV.gridx = 1;
    	gbc_parameterAESIV.gridy = 2;
    	panel.add(parameterAESIV, gbc_parameterAESIV);
    	
        chckbxNewCheckBox = new JCheckBox("IV block in Ciphertext");
        chckbxNewCheckBox.setEnabled(true);
    	GridBagConstraints gbc_chckbxNewCheckBox = new GridBagConstraints();
    	gbc_chckbxNewCheckBox.fill = GridBagConstraints.HORIZONTAL;
    	gbc_chckbxNewCheckBox.insets = new Insets(0, 0, 5, 0);
    	gbc_chckbxNewCheckBox.gridx = 1;
    	gbc_chckbxNewCheckBox.gridy = 3;
    	panel.add(chckbxNewCheckBox, gbc_chckbxNewCheckBox);

        chckbxEnableListeners = new JCheckBox("Enable Proxy and HTTP listeners");
        chckbxEnableListeners.setEnabled(true);
        GridBagConstraints gbc_chckbxEnableListeners = new GridBagConstraints();
        gbc_chckbxEnableListeners.fill = GridBagConstraints.HORIZONTAL;
        gbc_chckbxEnableListeners.insets = new Insets(0, 0, 5, 0);
        gbc_chckbxEnableListeners.gridx = 1;
        gbc_chckbxEnableListeners.gridy = 4;
        panel.add(chckbxEnableListeners, gbc_chckbxEnableListeners);

    	lbl4 = new JLabel("Ciphertext encoding:");
    	lbl4.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl4 = new GridBagConstraints();
    	gbc_lbl4.anchor = GridBagConstraints.EAST;
    	gbc_lbl4.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl4.gridx = 0;
        gbc_lbl4.gridy = 5;
    	panel.add(lbl4, gbc_lbl4);
    	
    	comboEncoding = new JComboBox();
    	comboEncoding.setModel(new DefaultComboBoxModel(new String[] {"Base 64", "ASCII Hex"}));
    	comboEncoding.setSelectedIndex(0);
    	GridBagConstraints gbc_comboEncoding = new GridBagConstraints();
    	gbc_comboEncoding.insets = new Insets(0, 0, 5, 0);
    	gbc_comboEncoding.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboEncoding.gridx = 1;
        gbc_comboEncoding.gridy = 5;
    	panel.add(comboEncoding, gbc_comboEncoding);
    	
    	lbl3 = new JLabel("AES Mode:");
    	lbl3.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lbl3 = new GridBagConstraints();
    	gbc_lbl3.insets = new Insets(0, 0, 5, 5);
    	gbc_lbl3.anchor = GridBagConstraints.EAST;
    	gbc_lbl3.gridx = 0;
        gbc_lbl3.gridy = 6;
    	panel.add(lbl3, gbc_lbl3);
    	
    	comboAESMode = new JComboBox();
    	comboAESMode.addPropertyChangeListener(new PropertyChangeListener() {
    		public void propertyChange(PropertyChangeEvent arg0) {
    			String cmode = (String)comboAESMode.getSelectedItem();
    			if (cmode.contains("CBC")) {
    				parameterAESIV.setEditable(true);
    			} else {
    				parameterAESIV.setEditable(false);
    			}
    		}
    	});
    	comboAESMode.setModel(new DefaultComboBoxModel(new String[] {"AES/CBC/NoPadding", "AES/CBC/PKCS5Padding", "AES/ECB/NoPadding", "AES/ECB/PKCS5Padding"}));
    	comboAESMode.setSelectedIndex(1);
    	GridBagConstraints gbc_comboAESMode = new GridBagConstraints();
    	gbc_comboAESMode.insets = new Insets(0, 0, 5, 0);
    	gbc_comboAESMode.fill = GridBagConstraints.HORIZONTAL;
    	gbc_comboAESMode.gridx = 1;
        gbc_comboAESMode.gridy = 6;
    	panel.add(comboAESMode, gbc_comboAESMode);
    	
    	panel_1 = new JPanel();
    	GridBagConstraints gbc_panel_1 = new GridBagConstraints();
    	gbc_panel_1.gridwidth = 2;
    	gbc_panel_1.fill = GridBagConstraints.BOTH;
    	gbc_panel_1.gridx = 0;
        gbc_panel_1.gridy = 7;
    	panel.add(panel_1, gbc_panel_1);
    	GridBagLayout gbl_panel_1 = new GridBagLayout();
    	gbl_panel_1.columnWidths = new int[]{0, 0, 0, 0};
    	gbl_panel_1.rowHeights = new int[]{0, 0, 0, 0};
    	gbl_panel_1.columnWeights = new double[]{1.0, 0.0, 1.0, Double.MIN_VALUE};
    	gbl_panel_1.rowWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
    	panel_1.setLayout(gbl_panel_1);
    	
    	lblPlaintext = new JLabel("Plaintext");
    	lblPlaintext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblPlaintext = new GridBagConstraints();
    	gbc_lblPlaintext.insets = new Insets(0, 0, 5, 5);
    	gbc_lblPlaintext.gridx = 0;
    	gbc_lblPlaintext.gridy = 0;
    	panel_1.add(lblPlaintext, gbc_lblPlaintext);
    	
    	lblCiphertext = new JLabel("Ciphertext");
    	lblCiphertext.setHorizontalAlignment(SwingConstants.RIGHT);
    	GridBagConstraints gbc_lblCiphertext = new GridBagConstraints();
    	gbc_lblCiphertext.insets = new Insets(0, 0, 5, 0);
    	gbc_lblCiphertext.gridx = 2;
    	gbc_lblCiphertext.gridy = 0;
    	panel_1.add(lblCiphertext, gbc_lblCiphertext);
    	
    	textAreaPlaintext = new JTextArea();
    	textAreaPlaintext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaPlaintext = new GridBagConstraints();
    	gbc_textAreaPlaintext.gridheight = 2;
    	gbc_textAreaPlaintext.insets = new Insets(0, 0, 0, 5);
    	gbc_textAreaPlaintext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaPlaintext.gridx = 0;
    	gbc_textAreaPlaintext.gridy = 1;
        plainTextScroll = new JScrollPane(textAreaPlaintext);
        panel_1.add(plainTextScroll, gbc_textAreaPlaintext);
    	
    	btnNewButton = new JButton("Encrypt ->");
    	btnNewButton.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {		
    	        try {
    	        	textAreaCiphertext.setText(encrypt(textAreaPlaintext.getText()));
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    			
    		}
    	});
    	GridBagConstraints gbc_btnNewButton = new GridBagConstraints();
    	gbc_btnNewButton.insets = new Insets(0, 0, 5, 5);
    	gbc_btnNewButton.gridx = 1;
    	gbc_btnNewButton.gridy = 1;
    	panel_1.add(btnNewButton, gbc_btnNewButton);
    	
    	textAreaCiphertext = new JTextArea();
    	textAreaCiphertext.setLineWrap(true);
    	GridBagConstraints gbc_textAreaCiphertext = new GridBagConstraints();
    	gbc_textAreaCiphertext.gridheight = 2;
    	gbc_textAreaCiphertext.fill = GridBagConstraints.BOTH;
    	gbc_textAreaCiphertext.gridx = 2;
    	gbc_textAreaCiphertext.gridy = 1;
        cipherTextScroll = new JScrollPane(textAreaCiphertext);
        panel_1.add(cipherTextScroll, gbc_textAreaCiphertext);
    	
    	btnNewButton_1 = new JButton("<- Decrypt");
    	btnNewButton_1.addActionListener(new ActionListener() {
    		public void actionPerformed(ActionEvent arg0) {
    	        try {
    	        	textAreaPlaintext.setText(decrypt(textAreaCiphertext.getText()));
    	        } catch(Exception e) {
    	        	callbacks.issueAlert(e.toString());
    	        }
    		}
    	});
    	btnNewButton_1.setVerticalAlignment(SwingConstants.TOP);
    	GridBagConstraints gbc_btnNewButton_1 = new GridBagConstraints();
    	gbc_btnNewButton_1.anchor = GridBagConstraints.NORTH;
    	gbc_btnNewButton_1.insets = new Insets(0, 0, 0, 5);
    	gbc_btnNewButton_1.gridx = 1;
    	gbc_btnNewButton_1.gridy = 2;
    	panel_1.add(btnNewButton_1, gbc_btnNewButton_1);
    }
 
    public void addMenuTab() {
        // create our UI
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
            	buildUI();
            	callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    
    @Override
    public String getTabCaption()
    {
        return "AES Crypto";
    }

    @Override
    public Component getUiComponent()
    {
		return panel;
    }
    
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    
	public static String byteArrayToHexString(byte[] b) {
		int len = b.length;
		String data = new String();
		for (int i = 0; i < len; i++){
			data += Integer.toHexString((b[i] >> 4) & 0xf);
			data += Integer.toHexString(b[i] & 0xf);
		}
		return data;
	}
    
    //
    // implement IScannerInsertionPointProvider
    //
    
    @Override
    public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse)
    {
    	// insertion points to return
        List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();
        
        // retrieve request parameters
    	IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse.getRequest());
    	List<IParameter> requestParams = requestInfo.getParameters();
    	
    	callbacks.issueAlert("Searching for AES encrypted data in request...");
    	
    	for (IParameter parameter : requestParams) {
    		String value = parameter.getValue();
    		value = helpers.urlDecode(value).trim();
    		
    		if (value.isEmpty()) continue;
    		
	        try {
            	String basevalue = decrypt(value);
            	String basename = parameter.getName();
            	callbacks.issueAlert("Will scan AES encrypted data at parameter " + basename + " with value " + basevalue);
            	// Add insertion point
            	insertionPoints.add(new InsertionPoint(this, baseRequestResponse.getRequest(), basename, basevalue));
	        } catch(Exception e) {
	        }
	        
    	}
    	
        return insertionPoints;
    }


    public String encrypt(String plainText) throws Exception {
    	
    	byte[] keyValue= hexStringToByteArray(parameterAESkey.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	
    	byte[] iv = hexStringToByteArray(parameterAESIV.getText());
    	IvParameterSpec ivSpec = new IvParameterSpec(iv);

        String cmode = (String)comboAESMode.getSelectedItem();
        
        Cipher cipher = Cipher.getInstance((String)comboAESMode.getSelectedItem());
        if (cmode.contains("CBC")) {
        	cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);
        } else {
        	cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        }

        byte[] encVal = cipher.doFinal(plainText.getBytes());

        if (chckbxNewCheckBox.isSelected()) {
            byte[] enc = cipher.doFinal(plainText.getBytes());
            encVal = new byte[iv.length + enc.length];
            System.arraycopy(iv, 0, encVal, 0, iv.length);
            System.arraycopy(enc, 0, encVal, iv.length, enc.length);
        }

        // This wont work for http requests either output ascii hex or url encoded values
        String encryptedValue = new String(encVal, "UTF-8");
        
        switch (comboEncoding.getSelectedItem().toString()) {
    		case "Base 64":
    			encryptedValue = helpers.base64Encode(encVal);
    			break;
    		case "ASCII Hex":
    			encryptedValue = byteArrayToHexString(encVal);
    			break;
        }
        
        return encryptedValue;
    }
    
    public String decrypt(String ciphertext) throws Exception {

    	byte[] keyValue= hexStringToByteArray(parameterAESkey.getText());
    	Key skeySpec = new SecretKeySpec(keyValue, "AES");
    	byte[] iv = hexStringToByteArray(parameterAESIV.getText());
        String cmode = (String)comboAESMode.getSelectedItem();
        
        byte [] cipherbytes = ciphertext.getBytes();
        
        switch (comboEncoding.getSelectedItem().toString()) {
        	case "Base 64":
        		cipherbytes = helpers.base64Decode(ciphertext);
        		break;
    		case "ASCII Hex":
    			cipherbytes = hexStringToByteArray(ciphertext);
    			break;
        }
        
        if (chckbxNewCheckBox.isSelected()) {
            iv = Arrays.copyOfRange(cipherbytes, 0, 16);
            cipherbytes = Arrays.copyOfRange(cipherbytes, 16, cipherbytes.length);
        }

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(cmode);
        if (cmode.contains("CBC")) {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        }

        byte[] original = cipher.doFinal(cipherbytes);
        return new String(original);
    	
    }

    // +--------+---------------+--------------+--------+--------------+---------------+--------+
    // |        |            REQUEST           |        |           RESPONSE           |        |
    // +        +---------------+--------------+        +--------------+---------------+        +
    // | CLIENT | ProxyListener | HttpListener | SERVER | HttpListener | ProxyListener | CLIENT |
    // +        +---------------+--------------+        +--------------+---------------+        +
    // |        |    decrypt    |   encrypt    |        |    decrypt   |    encrypt    |        |
    // +--------+---------------+--------------+--------+--------------+---------------+--------+

    //
    // implement IProxyListener
    //

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!chckbxEnableListeners.isSelected()) {
            return;
        }

        IHttpRequestResponse messageInfo = message.getMessageInfo();

        try {
            if (messageIsRequest) {
                byte[] request = messageInfo.getRequest();
                List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
                int bodyOffset = helpers.analyzeRequest(messageInfo).getBodyOffset();
                String method = helpers.analyzeRequest(messageInfo).getMethod();
                byte[] bodyArray = Arrays.copyOfRange(request, bodyOffset, request.length);
                String body = helpers.bytesToString(bodyArray).replaceAll("\r", "").replaceAll("\n", "");

                messageInfo.setRequest(
                    helpers.buildHttpMessage(
                        headers,
                        decrypt(body).getBytes()
                ));
            } else {
                byte[] response = messageInfo.getResponse();
                List<String> headers = helpers.analyzeResponse(response).getHeaders();
                int bodyOffset = helpers.analyzeResponse(response).getBodyOffset();
                byte[] bodyArray = Arrays.copyOfRange(response, bodyOffset, response.length);
                String body = helpers.bytesToString(bodyArray);

                if (body != null && !body.isEmpty()) {
                    messageInfo.setResponse(
                        helpers.buildHttpMessage(
                            headers,
                            encrypt(body).getBytes()
                    ));
                }
            }
        }
        catch(Exception e) {
        }

    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!chckbxEnableListeners.isSelected()) {
            return;
        }

        try {
            if (messageIsRequest) {
                byte[] request = messageInfo.getRequest();
                String method = helpers.analyzeRequest(messageInfo).getMethod();
                List<String> headers = helpers.analyzeRequest(messageInfo).getHeaders();
                int bodyOffset = helpers.analyzeRequest(messageInfo).getBodyOffset();
                byte[] bodyArray = Arrays.copyOfRange(request, bodyOffset, request.length);
                String body = helpers.bytesToString(bodyArray);

                if (method == "POST" && body != null && !body.isEmpty()) {
                    messageInfo.setRequest(
                        helpers.buildHttpMessage(
                            headers,
                            encrypt(body).getBytes()
                    ));
                }
            } else {
                byte[] request = messageInfo.getResponse();
                List<String> headers = helpers.analyzeResponse(messageInfo.getResponse()).getHeaders();
                int bodyOffset = helpers.analyzeResponse(request).getBodyOffset();
                byte[] bodyArray = Arrays.copyOfRange(request, bodyOffset, request.length);
                String body = helpers.bytesToString(bodyArray).replaceAll("\r", "").replaceAll("\n", "");

                messageInfo.setResponse(
                    helpers.buildHttpMessage(
                        headers,
                        decrypt(body).getBytes()
                ));
            }
        }
        catch(Exception e) {
        }

    }
}
