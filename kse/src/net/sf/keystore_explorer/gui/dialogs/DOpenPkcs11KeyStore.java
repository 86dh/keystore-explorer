/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2015 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.sf.keystore_explorer.gui.dialogs;

import java.awt.Container;
import java.awt.Dialog;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.text.MessageFormat;
import java.util.ResourceBundle;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.DefaultComboBoxModel;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;

import net.miginfocom.swing.MigLayout;
import net.sf.keystore_explorer.gui.CurrentDirectory;
import net.sf.keystore_explorer.gui.CursorUtil;
import net.sf.keystore_explorer.gui.FileChooserFactory;
import net.sf.keystore_explorer.gui.JEscDialog;
import net.sf.keystore_explorer.gui.PlatformUtil;
import net.sf.keystore_explorer.gui.error.DProblem;
import net.sf.keystore_explorer.gui.error.Problem;
import sun.security.pkcs11.SunPKCS11;
import static java.awt.Dialog.ModalityType.DOCUMENT_MODAL;

/**
 * Dialog used to retrieve the type to use in the creation of a new KeyStore.
 *
 */
public class DOpenPkcs11KeyStore extends JEscDialog {
	private static final long serialVersionUID = 3188619209680032281L;

	private static ResourceBundle res = ResourceBundle.getBundle("net/sf/keystore_explorer/gui/dialogs/resources");

	private static final String CANCEL_KEY = "CANCEL_KEY";

	private JRadioButton jrbUseExisting;
	private JLabel jlSelectProvider;
	private JComboBox<String> jcbPkcs11Provider;

	private JRadioButton jrbCreateNew;
	private JLabel jlP11Library;
	private JTextField jtfP11Library;
	private JButton jbP11LibraryBrowse;
	private JLabel jlSlotListIndex;
	private JSpinner jspSlotListIndex;
	
	private JPanel jpButtons;
	private JButton jbOK;
	private JButton jbCancel;

	private Provider selectedProvider;

	/**
	 * Creates a new DOpenPkcs11KeyStore dialog.
	 *
	 * @param parent
	 *            The parent frame
	 */
	public DOpenPkcs11KeyStore(JFrame parent) {
		super(parent, Dialog.ModalityType.DOCUMENT_MODAL);
		setTitle(res.getString("DOpenPkcs11KeyStore.Title"));
		initComponents();
	}

	private void initComponents() {
		
		jrbUseExisting = new JRadioButton(res.getString("DOpenPkcs11KeyStore.jrbUseExisting.text"), false);
		PlatformUtil.setMnemonic(jrbUseExisting, res.getString("DOpenPkcs11KeyStore.jrbUseExisting.mnemonic").charAt(0));
		
		jlSelectProvider = new JLabel(res.getString("DOpenPkcs11KeyStore.jlSelectProvider.text"));
		
		jcbPkcs11Provider = new JComboBox<String>(new DefaultComboBoxModel<String>(getPkcs11ProviderList()));
		jcbPkcs11Provider.setToolTipText(res.getString("DOpenPkcs11KeyStore.jcbPkcs11Provider.tooltip"));
		
		jrbCreateNew = new JRadioButton(res.getString("DOpenPkcs11KeyStore.jrbCreateNew.text"), false);
		PlatformUtil.setMnemonic(jrbCreateNew, res.getString("DOpenPkcs11KeyStore.jrbCreateNew.mnemonic").charAt(0));
		
		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(jrbUseExisting);
		buttonGroup.add(jrbCreateNew);
		
		if (getPkcs11ProviderList().length > 0) {
			jrbUseExisting.setSelected(true);
		} else {
			jrbCreateNew.setSelected(true);
			
			// no pre-defined p11 providers => disable that option
			jrbUseExisting.setEnabled(false);
			jlSelectProvider.setEnabled(false);
			jcbPkcs11Provider.setEnabled(false);
		}
		
		jlP11Library = new JLabel(res.getString("DOpenPkcs11KeyStore.jlP11Library.text"));
		
		jtfP11Library = new JTextField(30);
		jtfP11Library.setToolTipText(res.getString("DOpenPkcs11KeyStore.jtfP11Library.tooltip"));
		
		jbP11LibraryBrowse = new JButton();
		jbP11LibraryBrowse.setIcon(new ImageIcon(getClass().getResource(res.getString("DOpenPkcs11KeyStore.jbP11LibraryBrowse.image"))));
		jbP11LibraryBrowse.setToolTipText(res.getString("DOpenPkcs11KeyStore.jbP11LibraryBrowse.tooltip"));

		jlSlotListIndex = new JLabel(res.getString("DOpenPkcs11KeyStore.jlSlotListIndex.text"));

		jspSlotListIndex = new JSpinner();
		jspSlotListIndex.setModel(new SpinnerNumberModel(0, 0, 65000, 1));
		jspSlotListIndex.setToolTipText(res.getString("DOpenPkcs11KeyStore.jspSlotListIndex.tooltip"));
		
		jbOK = new JButton(res.getString("DOpenPkcs11KeyStore.jbOK.text"));

		jbCancel = new JButton(res.getString("DOpenPkcs11KeyStore.jbCancel.text"));
		jbCancel.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				CANCEL_KEY);

		jpButtons = PlatformUtil.createDialogButtonPanel(jbOK, jbCancel);

        Container pane = getContentPane();
        pane.setLayout(new MigLayout("insets dialog, fill", "[para]rel[]rel[grow][]", ""));
        pane.add(jrbUseExisting, "spanx, wrap");
        pane.add(jlSelectProvider, "skip");
        pane.add(jcbPkcs11Provider, "growx, wrap unrel");
        pane.add(jrbCreateNew, "spanx, wrap");
        pane.add(jlP11Library, "skip");
        pane.add(jtfP11Library, "");
        pane.add(jbP11LibraryBrowse, "wrap");
        pane.add(jlSlotListIndex, "skip");
        pane.add(jspSlotListIndex, "wrap para");
        pane.add(new JSeparator(), "spanx, growx, wrap para");
        pane.add(jpButtons, "right, spanx");

        jbP11LibraryBrowse.addActionListener(new java.awt.event.ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				try {
					CursorUtil.setCursorBusy(DOpenPkcs11KeyStore.this);
					browsePressed();
				} finally {
					CursorUtil.setCursorFree(DOpenPkcs11KeyStore.this);
				}
			}
        });
        
		jbCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		
		jbCancel.getActionMap().put(CANCEL_KEY, new AbstractAction() {
			public void actionPerformed(ActionEvent evt) {
				cancelPressed();
			}
		});
		
		jbOK.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				okPressed();
			}
		});

		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent evt) {
				closeDialog();
			}
		});

		setResizable(false);

		getRootPane().setDefaultButton(jbOK);

		pack();
	}

	private String[] getPkcs11ProviderList() {
		
		Provider[] providers = Security.getProviders("KeyStore.PKCS11");
		
		if (providers == null) {
			return new String[0];
		}
		
		String[] providerNames = new String[providers.length];
		
		for (int i = 0; i < providers.length; i++) {
			providerNames[i] = providers[i].getName();
		}
		
		return providerNames;
	}
	
	private void browsePressed() {
		JFileChooser chooser = FileChooserFactory.getLibFileChooser();

		File currentLibFile = new File(jtfP11Library.getText().trim());

		if ((currentLibFile.getParentFile() != null) && (currentLibFile.getParentFile().exists())) {
			chooser.setCurrentDirectory(currentLibFile.getParentFile());
			chooser.setSelectedFile(currentLibFile);
		} else {
			chooser.setCurrentDirectory(CurrentDirectory.get());
		}

		chooser.setDialogTitle(res.getString("DOpenPkcs11KeyStore.SelectLib.Title"));
		chooser.setMultiSelectionEnabled(false);

		int rtnValue = chooser.showDialog(this, res.getString("DOpenPkcs11KeyStore.SelectLib.button"));
		if (rtnValue == JFileChooser.APPROVE_OPTION) {
			File chosenFile = chooser.getSelectedFile();
			CurrentDirectory.updateForFile(chosenFile);
			jtfP11Library.setText(chosenFile.toString());
			jtfP11Library.setCaretPosition(0);
		}
	}

	private void okPressed() {
		
		try {
			if (jrbUseExisting.isSelected()) {

				String providerName = (String) jcbPkcs11Provider.getSelectedItem();
				selectedProvider = Security.getProvider(providerName);

				if (selectedProvider == null) {
					JOptionPane.showMessageDialog(this,
							res.getString("DOpenPkcs11KeyStore.providerNotInstalled.message"), getTitle(),
							JOptionPane.WARNING_MESSAGE);
				}
			} else {

				if (jtfP11Library.getText().isEmpty()) {
					JOptionPane.showMessageDialog(this, res.getString("DOpenPkcs11KeyStore.noLibSelected.message"),
							getTitle(), JOptionPane.WARNING_MESSAGE);
					return;
				}

				String pkcs11ConfigSettings = "name = Slot" + jspSlotListIndex.getValue() + "\n" + "library = "
						+ jtfP11Library.getText() + "\n" + "slotListIndex = " + jspSlotListIndex.getValue() + "";
				ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11ConfigSettings.getBytes());

				// instantiate the provider
				SunPKCS11 pkcs11 = new SunPKCS11(confStream);
				Security.addProvider(pkcs11);
				selectedProvider = pkcs11;
			}
			
			closeDialog();
		} catch (final ProviderException e) {
			SwingUtilities.invokeLater(new Runnable() {
				public void run() {
					if (DOpenPkcs11KeyStore.this.isShowing()) {
						String problemStr = MessageFormat.format(
								res.getString("DOpenPkcs11KeyStore.ProblemLoadingProvider.Problem"), jtfP11Library.getText());

						String[] causes = new String[] { res.getString("DOpenPkcs11KeyStore.NotPkcs11Lib.Cause"),
								res.getString("DOpenPkcs11KeyStore.32with64bit.Cause"),
								res.getString("DOpenPkcs11KeyStore.64bitBeforeJRE8.Cause"),
								res.getString("DOpenPkcs11KeyStore.WrongConfiguration.Cause")};

						Problem problem = new Problem(problemStr, causes, e);

						DProblem dProblem = new DProblem(DOpenPkcs11KeyStore.this, res
								.getString("DOpenPkcs11KeyStore.ProblemLoadingProvider.Title"), DOCUMENT_MODAL, problem);
						dProblem.setLocationRelativeTo(DOpenPkcs11KeyStore.this);
						dProblem.setVisible(true);
					}
				}
			});
		}
	}

	private void cancelPressed() {
		closeDialog();
	}

	private void closeDialog() {
		setVisible(false);
		dispose();
	}
	
	public Provider getSelectedProvider() {
		return this.selectedProvider;
	}
}
