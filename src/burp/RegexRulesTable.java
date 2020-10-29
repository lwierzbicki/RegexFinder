package burp;

import javax.swing.*;
import javax.swing.filechooser.FileSystemView;
import javax.swing.table.DefaultTableModel;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * This class creates table, which stores list of regex rules.
 *
 *
 * Code was based and adapted from https://github.com/augustd/burp-suite-utils
 *
 * Original authors:
 * @author August Detlefsen
 */

public class RegexRulesTable extends javax.swing.JPanel {


    private javax.swing.JLabel headerText;
    private javax.swing.JTable rules;
    private javax.swing.JScrollPane scrollPane;
    private javax.swing.JButton loadButton;
    private javax.swing.JButton addButton;
    private javax.swing.JButton removeButton;
    private javax.swing.JButton clearButton;
    IBurpExtenderCallbacks mCallbacks;
    RegexScan scan;

    public RegexRulesTable(IBurpExtenderCallbacks callbacks, RegexScan scan) {

        mCallbacks = callbacks;
        this.scan = scan;

        initComponents();

        mCallbacks.customizeUiComponent(rules);

        //add a listener for changes to the table model
        final DefaultTableModel model = (DefaultTableModel)rules.getModel();
        model.addTableModelListener(new TableModelListener() {
            @Override
            public void tableChanged(TableModelEvent e) {
            }
        });
    }

    private void initComponents() {

        headerText = new JLabel();
        scrollPane = new JScrollPane();
        rules = new JTable();
        loadButton = new JButton();
        addButton = new JButton();
        removeButton = new JButton();
        clearButton = new JButton();

        rules.setModel(new DefaultTableModel(
                new Object [][] {

                },
                new String [] {
                        "Regex Type", "Description", "Regex"
                }
        ) {
            Class[] types = new Class [] {
                    String.class, String.class, String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });

        scrollPane.setViewportView(rules);

        headerText.setText("Regular expressions table to check responses");

        loadButton.setText("Load");
        loadButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                loadButtonActionPerformed(evt);
            }
        });

        addButton.setText("Add");
        addButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                addButtonActionPerformed(evt);
            }
        });

        removeButton.setText("Remove");
        removeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                removeButtonActionPerformed(evt);
            }
        });

        clearButton.setText("Clear");
        clearButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                clearButtonActionPerformed(evt);
            }
        });

        GroupLayout layout = new GroupLayout(this);
        this.setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        // Create a sequential group for the horizontal axis.
        GroupLayout.SequentialGroup hGroup = layout.createSequentialGroup();
        hGroup.addGroup(layout.createParallelGroup().
                addComponent(headerText).addComponent(scrollPane).
                addGroup(layout.createSequentialGroup().
                        addComponent(loadButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).
                        addComponent(addButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).
                        addComponent(removeButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE).
                        addComponent(clearButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));
        layout.setHorizontalGroup(hGroup);

        // Create a sequential group for the vertical axis.
        GroupLayout.SequentialGroup vGroup = layout.createSequentialGroup();
        vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).
                addComponent(headerText));
        vGroup.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
        vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).
                addComponent(scrollPane));
        vGroup.addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED);
        vGroup.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).
                addComponent(loadButton).addComponent(addButton).addComponent(removeButton).addComponent(clearButton));
        layout.setVerticalGroup(vGroup);


    }

    private void loadButtonActionPerformed(java.awt.event.ActionEvent evt) {
        JFileChooser j = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        // invoke the showsOpenDialog function to show the save dialog
        int r = j.showOpenDialog(null);
        // if the user selects a file
        if (r == JFileChooser.APPROVE_OPTION)
        {
            // set the label to the path of the selected file
            //mCallbacks.printOutput(j.getSelectedFile().getAbsolutePath());
            loadMatchRules(j.getSelectedFile().getAbsolutePath());
        }
        // if the user cancelled the operation
        else
            mCallbacks.printOutput("the user cancelled the operation");

    }

    private void addButtonActionPerformed(java.awt.event.ActionEvent evt) {
        DefaultTableModel model = (DefaultTableModel)rules.getModel();
        model.addRow(new Object[]{"", "", ""});
    }

    private void removeButtonActionPerformed(java.awt.event.ActionEvent evt) {
        DefaultTableModel model = (DefaultTableModel)rules.getModel();
        int[] rows = rules.getSelectedRows();
        for (int i = 0; i < rows.length; i++) {
            model.removeRow(rows[i] - i);
            scan.removeRegexRule(rows[i] - i);
        }
    }

    private void clearButtonActionPerformed(java.awt.event.ActionEvent evt) {
        //clear the existing values from the table
        DefaultTableModel model = (DefaultTableModel) rules.getModel();
        model.setRowCount(0);
        //remove existing match rules from the scan
        scan.clearRegexRules();
    }

    private boolean loadMatchRules(String rulesUrl) {
        try{
            mCallbacks.printOutput("Loading match rules from file: " + rulesUrl);
            InputStream in = new FileInputStream(rulesUrl);
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            processMatchRules(reader);
            return true;

        } catch (IOException e) {
            mCallbacks.printError(String.valueOf(e));
        } catch (NumberFormatException e) {
            mCallbacks.printError(String.valueOf(e));
        }

        return false;
    }


    private void processMatchRules(BufferedReader reader) throws IOException {
        DefaultTableModel model = (DefaultTableModel)rules.getModel();

        String str;
        while ((str = reader.readLine()) != null) {
            //mCallbacks.printOutput("str: " + str);
            if (str.trim().length() == 0) {
                continue;
            }

            String[] values = str.split("\\t");
            model.addRow(values);

            //?
            try {
                Pattern pattern = Pattern.compile(values[2]);

                scan.addRegexRule(new RegexRule(
                        values[0],
                        values[1],
                        pattern)
                );
            } catch (PatternSyntaxException pse) {
                //in case the match pattern is invalid
                mCallbacks.printError("Invalid match pattern: " + values[2]);

            }
        }
    }

}
