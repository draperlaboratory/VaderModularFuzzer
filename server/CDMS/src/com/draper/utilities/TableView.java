/* =============================================================================
 * Vader Modular Fuzzer (VMF)
 * Copyright (c) 2021-2023 The Charles Stark Draper Laboratory, Inc.
 * <vader@draper.com>
 *  
 * Effort sponsored by the U.S. Government under Other Transaction number
 * W9124P-19-9-0001 between AMTC and the Government. The U.S. Government
 * Is authorized to reproduce and distribute reprints for Governmental purposes
 * notwithstanding any copyright notation thereon.
 *  
 * The views and conclusions contained herein are those of the authors and
 * should not be interpreted as necessarily representing the official policies
 * or endorsements, either expressed or implied, of the U.S. Government.
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 (only) as 
 * published by the Free Software Foundation.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
 * @license GPL-2.0-only <https://spdx.org/licenses/GPL-2.0-only.html>
 * ===========================================================================*/
package com.draper.utilities;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import java.awt.Dimension;

public class TableView extends JFrame implements ActionListener
{
    private static final long serialVersionUID = 1L;
	private JMenuBar 	      mb;
	private JMenu 	  	      file, edit, help;
	private JMenuItem 	      cut, copy, paste, selectAll;

    /**********************************************************************************************
     * 
     * @return
     */
	public TableView( TableContainer tc )
	{
        DefaultTableModel tableModel  = new DefaultTableModel(tc.getColumnNames(), tc.getRowCount());       
        
        for(int row = 0; row < tc.getRowCount(); row++)
        {
           tableModel.insertRow(row, tc.getRowData(row));
        }
        
        buildPanel(tableModel);
	}
	
    /**********************************************************************************************
     * 
     * @return
     */
	public void buildPanel(DefaultTableModel tableModel )
	{
		cut = new JMenuItem("Cut");
		copy = new JMenuItem("Copy");
		paste = new JMenuItem("Paste");
		selectAll = new JMenuItem("SelectAll");
	
		cut.addActionListener(this);
		copy.addActionListener(this);
		paste.addActionListener(this);
		selectAll.addActionListener(this);
	
		mb = new JMenuBar();
		file = new JMenu("File");
		edit = new JMenu("Edit");
		help = new JMenu("Help");
		file.add(new JMenuItem("Open"));
		edit.add(cut);
		edit.add(copy);
		edit.add(paste);
		edit.add(selectAll);
		mb.add(file);
		mb.add(edit);
		mb.add(help);
		
        JTable table = new JTable(tableModel);
        table.setSize(3000, 1000);
        JScrollPane sp = new JScrollPane(table);
        sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        sp.setPreferredSize(new Dimension(1500, 600));

        // Complete the Panel
        
        this.add(sp);		
		this.setJMenuBar(mb);
		this.setTitle("Key Algorithm Input Parameters");
		this.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
		this.setSize(1500, 1000);
	}

    /**********************************************************************************************
     * 
     * @return
     */

    public void togglePanel(boolean show)
    {
        this.setVisible(show);
    }

    /**********************************************************************************************
     * 
     * @return
     */

	public void actionPerformed(ActionEvent e)
	{
		// TODO Auto-generated method stub
	}
}
