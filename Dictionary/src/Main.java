import  javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.*;
class Util {
    public static void setupAutoComplete(final JTextField txtInput, ArrayList<String> items) {
        final var model = new DefaultComboBoxModel();
        final var cbInput = new JComboBox(model) {
            public Dimension getPreferredSize() {
                return new Dimension(super.getPreferredSize().width, 0);
            }
        };
        setAdjusting(cbInput, false);
        if (items != null) {
            for (String item : items) {
                model.addElement(item);
            }
        }
        cbInput.setSelectedItem(null);
        cbInput.addActionListener(e -> {
            if (!isAdjusting(cbInput)) {
                if (cbInput.getSelectedItem() != null) {
                    txtInput.setText(cbInput.getSelectedItem().toString());
                }
            }
        });
        txtInput.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                setAdjusting(cbInput, true);
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
                    if (cbInput.isPopupVisible()) {
                        e.setKeyCode(KeyEvent.VK_ENTER);
                    }
                }
                if (e.getKeyCode() == KeyEvent.VK_ENTER || e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    e.setSource(cbInput);
                    cbInput.dispatchEvent(e);
                    if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                        txtInput.setText((String) cbInput.getSelectedItem());
                        cbInput.setPopupVisible(false);
                    }
                }
                if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
                    cbInput.setPopupVisible(false);
                }
                setAdjusting(cbInput, false);
            }
        });
        txtInput.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                updateList();
            }
            public void removeUpdate(DocumentEvent e) {
                updateList();
            }
            public void changedUpdate(DocumentEvent e) {
                updateList();
            }
            private void updateList() {
                setAdjusting(cbInput, true);
                model.removeAllElements();
                String input = txtInput.getText();
                if (!input.isEmpty()) {
                    assert items != null;
                    for (String item : items) {
                        if (item.toLowerCase().startsWith(input.toLowerCase())) {
                            model.addElement(item);
                        }
                    }
                }
                cbInput.setPopupVisible(model.getSize() > 0);
                setAdjusting(cbInput, false);
            }
        });
        txtInput.setLayout(new BorderLayout());
        txtInput.add(cbInput, BorderLayout.SOUTH);
    }
    private static void setAdjusting(JComboBox cbInput, boolean adjusting) {
        cbInput.putClientProperty("is_adjusting", adjusting);
    }
    private static boolean isAdjusting(JComboBox cbInput) {
        if (cbInput.getClientProperty("is_adjusting") instanceof Boolean) {
            return (Boolean) cbInput.getClientProperty("is_adjusting");
        }
        return false;
    }
}
class howToUse{
    final JFrame frame1;
    final Color col1=new Color(153,253,224);
    public howToUse() {
        frame1 = new JFrame("How to use");
        frame1.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        frame1.setBounds(500, 150, 500, 500);
        frame1.setResizable(false);
        frame1.setLayout(null);
        Container c = frame1.getContentPane();
        frame1.setVisible(true);
        JTextArea meaning=new JTextArea();
        meaning.setText("Search for a word= Ctrl+Enter\nAdd a word= Ctrl++\nModify the meaning= Ctrl+M\nSave a new word= Ctrl+S");
        meaning.setBounds(0,0,484,410);
        Font f1=new Font("Times new roman",Font.PLAIN,16);
        meaning.setFont(f1);
        meaning.setBackground(col1);
        meaning.setEditable(false);
        meaning.setWrapStyleWord(true);
        meaning.setLineWrap(true);
        JButton add1=new JButton("OK");
        add1.addActionListener(e -> frame1.dispose());
        meaning.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                frame1.dispose();
            }
        });
        add1.setBounds(0,410,485,50);
        c.add(add1);
        c.add(meaning);
    }
}
class Add implements FocusListener, ActionListener, KeyListener {
    final JFrame frame;
    final Color col1=new Color(153,253,224);
    final Color col2=new Color(65,26,247);
    final JButton add1;
    final JTextField search;
    final JTextArea meaning;
    String txt,s;
    final File file = new File("dictionary.txt");
    public void click(){
        if(meaning.getText().equals("Enter the meaning on the single paragraph") || search.getText().equals("Enter the word")){
            JOptionPane.showMessageDialog(frame,"All fields are required","Failure",JOptionPane.ERROR_MESSAGE);
        }
        else if(search.getText().length()>45){
            JOptionPane.showMessageDialog(frame,"Word length is too long","Info",JOptionPane.INFORMATION_MESSAGE);
        }
        else if(meaning.getText().contains("\n")){
            JOptionPane.showMessageDialog(frame,"Enter key is not allowed","Info",JOptionPane.INFORMATION_MESSAGE);
        }
        else {
            txt = search.getText().toLowerCase() + "\t" + meaning.getText().toLowerCase();
            try {
                int c = 0;
                FileReader fw = new FileReader(file);
                BufferedReader gr = new BufferedReader(fw);
                while ((s = gr.readLine()) != null) {
                    String word = s.split("\t")[0];
                    if (word.equals(search.getText().toLowerCase())) {
                        c++;
                    }
                }
                if (c == 0) {
                    FileWriter fr = new FileWriter(file, true);
                    BufferedWriter br = new BufferedWriter(fr);
                    br.write(txt + "\n");
                    br.close();
                    JOptionPane.showMessageDialog(frame, "Word added successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
                }
                else{
                    JOptionPane.showMessageDialog(frame, "Record Exists", "Failure", JOptionPane.INFORMATION_MESSAGE);
                }
                meaning.setText("Enter the meaning on the single paragraph");
                search.setText("Enter the word");
                gr.close();
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        }
    }
    public Add(){
        frame=new JFrame("Add a new word");
        frame.setBounds(250,50,1000,700);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(false);
        frame.setLayout(null);
        ImageIcon icon=new ImageIcon("D:/Java Programs/Dictionary/src/dictionary.png");
        frame.setIconImage(icon.getImage());
        Container c=frame.getContentPane();
        c.setBackground(col1);
        JMenuBar menuBar=new JMenuBar();
        menuBar.setBounds(0,0,1000,20);
        menuBar.setBackground(Color.black);
        JMenu help=new JMenu("Help");
        help.setForeground(Color.white);
        JMenuItem howToUse=new JMenuItem("View shortcut keys");
        howToUse.setForeground(Color.white);
        howToUse.setBackground(Color.black);
        howToUse.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e1) {
                new howToUse();
            }
        });
        KeyStroke helpbtn
                = KeyStroke.getKeyStroke(KeyEvent.VK_F1,KeyEvent.CTRL_DOWN_MASK);
        howToUse.setAccelerator(helpbtn);
        help.add(howToUse);
        JMenuItem back=new JMenuItem("Back");
        back.setForeground(Color.white);
        back.setBackground(Color.black);
        back.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.dispose();
                new Dictionaryapp();
            }
        });
        KeyStroke keyStrokeToOpen
                = KeyStroke.getKeyStroke(KeyEvent.VK_F2, KeyEvent.CTRL_DOWN_MASK);
        back.setAccelerator(keyStrokeToOpen);
        help.add(back);
        menuBar.add(help);
        c.add(menuBar);
        JPanel menu=new JPanel(null);
        menu.setBounds(220,100,550,400);
        menu.setBackground(col2);
        search=new JTextField("Enter the word");
        search.setBounds(25,0,500,40);
        search.addFocusListener(this);
        search.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                try{
                    search.setEditable(e.getKeyChar() < '0' || e.getKeyChar() > '9');
                }catch (NullPointerException e1){
                    System.out.println(" ");
                }
            }
        });
        menu.add(search);
        JPanel meaningmenu=new JPanel();
        meaningmenu.setBounds(25,45,500,300);
        meaningmenu.setBackground(col2);
        meaning=new JTextArea(17,45);
        meaning.setText("Enter the meaning on the single paragraph");
        meaning.setBounds(25,45,500,300);
        Font f1=new Font("Times new roman",Font.PLAIN,16);
        meaning.setFont(f1);
        meaning.setWrapStyleWord(true);
        meaning.setLineWrap(true);
        meaning.addFocusListener(this);
        meaning.addKeyListener(this);
        JScrollPane scroll=new JScrollPane(meaning);
        meaningmenu.add(scroll);
        menu.add(meaningmenu);
        add1=new JButton("Add");
        add1.addActionListener(this);
        Action saveAction=new AbstractAction("save") {
            @Override
            public void actionPerformed(ActionEvent e) {
                click();
            }
        };
        String key1="save";
        add1.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_S, KeyEvent.CTRL_DOWN_MASK),key1);
        add1.getActionMap().put(key1,saveAction);
        add1.setBounds(0,350,550,50);
        menu.add(add1);
        c.add(menu);
        frame.setVisible(true);
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        if(e.getActionCommand().equals("Add")) {
            click();
        }
    }
    @Override
    public void focusGained(FocusEvent e) {
        if(e.getComponent().equals(search)){
            if (search.getText().equals("Enter the word")){
                search.setText(null);
            }
        }
        else if(e.getComponent().equals(meaning)){
            if(meaning.getText().equals("Enter the meaning on the single paragraph")){
                meaning.setText(null);
            }
        }
    }
    @Override
    public void focusLost(FocusEvent e) {
        if(e.getComponent().equals(search)){
            if (search.getText().equals("")){
                search.setText("Enter the word");
            }
        }
        else if(e.getComponent().equals(meaning)){
            if(meaning.getText().equals("")){
                meaning.setText("Enter the meaning on the single paragraph");
            }
        }
    }
    @Override
    public void keyTyped(KeyEvent e) {}
    @Override
    public void keyPressed(KeyEvent e) {
        if(e.getKeyCode()==10){
            e.consume();
        }
    }
    @Override
    public void keyReleased(KeyEvent e) {}
}
class Dictionaryapp implements ActionListener, FocusListener, KeyListener{
    JList<String> list;
    JFrame frame;
    final Color col1=new Color(153,253,224);
    final Color col2=new Color(65,26,247);
    JButton add1,modify,searchbtn;
    JTextField search,suggest;
    JTextArea meaning;
    DefaultListModel<String> l1;
    String tempmeaning,s,tempword;
    final File file = new File("dictionary.txt");
    final ArrayList<String> array=new ArrayList<>();
    private void searchFilter(String searchTerm) {
        DefaultListModel filteredItems=new DefaultListModel();
        array.forEach((star) -> {
            String starName= star.toLowerCase();
            if (starName.startsWith(searchTerm.toLowerCase())) {
                filteredItems.addElement(star);
            }
        });
        l1=filteredItems;
        list.setModel(l1);
    }
    public void click(){
        if (search.getText().equals("Enter the word")) {
            JOptionPane.showMessageDialog(frame, "Enter a word to be searched", "Error", JOptionPane.ERROR_MESSAGE);
        }
        else {
            int c2 = 0;
            try {
                FileReader fw = new FileReader(file);
                BufferedReader gr = new BufferedReader(fw);
                while ((s = gr.readLine()) != null) {
                    String w = s.split("\t")[0];
                    if (w.equals(search.getText().toLowerCase())) {
                        meaning.setText(s.split("\t")[1]);
                        c2++;
                        modify.setVisible(true);
                        add1.setBounds(275, 350, 275, 50);
                        tempword = search.getText().toLowerCase();
                        tempmeaning=meaning.getText().toLowerCase();
                        search.setEnabled(true);
                    }
                }
                if (c2 == 0) {
                    meaning.setText("No meaning found");
                    modify.setVisible(false);
                    add1.setBounds(0,350,550,50);
                }
                gr.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }
    public Dictionaryapp () {
        try {
            FileReader fw = new FileReader(file);
            BufferedReader gr = new BufferedReader(fw);
            while ((s = gr.readLine()) != null) {
                String w = s.split("\t")[0];
                array.add(w);
            }
            gr.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Collections.sort(array);
        frame=new JFrame("Dictionary App");
        frame.setBounds(250,50,1000,700);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setResizable(false);
        frame.setLayout(null);
        frame.getRootPane().setDefaultButton(searchbtn);
        ImageIcon icon=new ImageIcon("D:/Java Programs/Dictionary/src/dictionary.png");
        frame.setIconImage(icon.getImage());
        Container c=frame.getContentPane();
        c.setBackground(col1);
        JMenuBar menuBar=new JMenuBar();
        menuBar.setBounds(0,0,1000,20);
        menuBar.setBackground(Color.black);
        JMenu help=new JMenu("Help");
        help.setForeground(Color.white);
        JMenuItem howToUse=new JMenuItem("View shortcut keys");
        howToUse.setForeground(Color.white);
        howToUse.setBackground(Color.black);
        howToUse.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new howToUse();
            }
        });
        KeyStroke helpbtn
                = KeyStroke.getKeyStroke(KeyEvent.VK_F1,KeyEvent.CTRL_DOWN_MASK);
        howToUse.setAccelerator(helpbtn);
        help.add(howToUse);
        menuBar.add(help);
        c.add(menuBar);
        l1 = new DefaultListModel<>();
        l1.addAll(array);
        JPanel panel=new JPanel(null);
        panel.setBounds(10,25,320,640);
        panel.setBackground(col1);
        suggest=new JTextField("Suggest");
        suggest.setBounds(0,0,320,20);
        panel.add(suggest);
        suggest.addFocusListener(this);
        suggest.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                searchTxtKeyReleased(e);
            }
        });
        JPanel panel1=new JPanel();
        panel1.setBounds(0,16,320,640);
        panel1.setBackground(col1);
        list = new JList<>(l1);
        list.setBounds(0,0, 310,640);
        list.setFixedCellWidth(300);
        list.revalidate();
        list.setModel(l1);
        list.setSelectedIndex(0);
        list.setFocusable(true);
        list.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    String item = list.getSelectedValue();
                    search.setText(item);
                    click();
                }
            }
        });
        panel1.add(list);
        JScrollPane scroll1=new JScrollPane(list,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        list.setVisibleRowCount(33);
        panel1.add(scroll1);
        panel.add(panel1);
        c.add(panel);
        JPanel menu=new JPanel(null);
        menu.setBounds(357,100,550,400);
        menu.setBackground(col2);
        search=new JTextField("Enter the word");
        search.setBounds(25,0,400,40);
        Util.setupAutoComplete(search, array);
        search.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {}
            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyCode()==KeyEvent.VK_ENTER) {
                    click();
                }
            }
            @Override
            public void keyReleased(KeyEvent e) {}
        });
        search.addFocusListener(this);
        menu.add(search);
        searchbtn=new JButton("Search");
        Action saveAction=new AbstractAction("search") {
            @Override
            public void actionPerformed(ActionEvent e) {
                click();
            }
        };
        String key="search";
        searchbtn.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK),key);
        searchbtn.getActionMap().put(key,saveAction);
        searchbtn.addActionListener(this);
        searchbtn.setBounds(425,0,100,40);
        menu.add(searchbtn);
        JPanel meaningmenu=new JPanel();
        meaningmenu.setBounds(25,45,500,300);
        meaningmenu.setBackground(col2);
        meaning=new JTextArea(17,45);
        meaning.setBounds(25,45,500,300);
        Font f1=new Font("Times new roman",Font.PLAIN,16);
        meaning.setFont(f1);
        meaning.setEditable(false);
        meaning.setWrapStyleWord(true);
        meaning.setLineWrap(true);
        meaning.addKeyListener(this);
        JScrollPane scroll=new JScrollPane(meaning);
        meaningmenu.add(scroll);
        menu.add(meaningmenu);
        modify=new JButton("Modify");
        modify.addActionListener(this);
        modify.setBounds(0,350,275,50);
        modify.setVisible(false);
        Action modifyAction=new AbstractAction("modify") {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!meaning.getText().equals("")){
                    JOptionPane.showMessageDialog(frame,"Enter a new meaning.. Press F11 when done","Modify",JOptionPane.PLAIN_MESSAGE);
                    meaning.setEditable(true);
                }
            }
        };
        String key1="modify";
        searchbtn.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_M, KeyEvent.CTRL_DOWN_MASK),key1);
        searchbtn.getActionMap().put(key1,modifyAction);
        menu.add(modify);
        add1=new JButton("Add a new word");
        Action addAction=new AbstractAction("add") {
            @Override
            public void actionPerformed(ActionEvent e) {
                frame.dispose();
                new Add();
            }
        };
        String key2="add";
        searchbtn.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ADD, KeyEvent.CTRL_DOWN_MASK),key2);
        searchbtn.getActionMap().put(key2,addAction);
        add1.addActionListener(this);
        add1.setBounds(0,350,550,50);
        menu.add(add1);
        c.add(menu);
        frame.setVisible(true);
    }
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("Add a new word")) {
            frame.dispose();
            new Add();
        }
        else if (e.getActionCommand().equals("Search")) {
            click();
        }
        else if (e.getActionCommand().equals("Modify")) {
            JOptionPane.showMessageDialog(frame,"Enter a new meaning.. Press F11 when done","Modify",JOptionPane.PLAIN_MESSAGE);
            meaning.setEditable(true);
        }
    }
    @Override
    public void focusGained(FocusEvent e) {
        if(e.getComponent().equals(search)){
            if (search.getText().equals("Enter the word")){
                search.setText(null);
            }
        }
        else if(e.getComponent().equals(suggest)){
            if(suggest.getText().equals("Suggest")){
                suggest.setText(null);
            }
        }
    }
    @Override
    public void focusLost(FocusEvent e) {
        if(e.getComponent().equals(search)){
            if (search.getText().equals("")){
                search.setText("Enter the word");
            }
        }
        else if(e.getComponent().equals(suggest)){
            if(suggest.getText().equals("")){
                suggest.setText("Suggest");
            }
        }
    }
    @Override
    public void keyTyped(KeyEvent e) {}
    @Override
    public void keyPressed(KeyEvent e) {
        if(e.getKeyCode()==10){
            e.consume();
        }
        else if(e.getKeyCode()==122){
            if(meaning.getText().equals("")){
                modify.setVisible(false);
                add1.setBounds(0,350,550,50);
                meaning.setEditable(false);
                search.setText("Enter the word");
            }
            else if(meaning.getText().contains("\n")){
                JOptionPane.showMessageDialog(frame,"Enter key is not allowed","Info",JOptionPane.INFORMATION_MESSAGE);
            }
            else if(search.getText().length()>45){
                JOptionPane.showMessageDialog(frame,"Word length is too long","Info",JOptionPane.INFORMATION_MESSAGE);
            }
            else {
                try {
                    String oldstring = tempword + "\t" + tempmeaning;
                    String newstring = tempword + "\t" + meaning.getText().toLowerCase();
                    Scanner sc = new Scanner(file);
                    StringBuilder buffer = new StringBuilder();
                    while (sc.hasNextLine()) {
                        buffer.append(sc.nextLine()).append(System.lineSeparator());
                    }
                    String fileContents = buffer.toString();
                    sc.close();
                    fileContents = fileContents.replace(oldstring, newstring);
                    FileWriter writer = new FileWriter(file);
                    writer.append(fileContents);
                    writer.flush();
                    JOptionPane.showMessageDialog(frame,"Word modified successfully","Success",JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
    }
    private void searchTxtKeyReleased(java.awt.event.KeyEvent evt) {
        searchFilter(suggest.getText());
    }
    @Override
    public void keyReleased(KeyEvent e) {}
}
public class Main{
    public static void main(String[] args) {
        new Dictionaryapp();
    }
}