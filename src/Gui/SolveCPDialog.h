/*
 * Copyright (c) 2016 Mark Liversedge (liversedge@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "GoldenCheetah.h"

#include <QDialog>
#include <QLabel>
#include <QCheckBox>
#include <QWidget>
#include <QTreeWidget>

class Context;
class SolveCPDialog : public QDialog
{
    Q_OBJECT
    G_OBJECT


    public:
        SolveCPDialog(QWidget *parent, Context *);

    private:

        // General labels
        QLabel *dataLabel, *progressLabel, *bestLabel, *currentLabel;

        // data side of the dialog
        QCheckBox *selectCheckBox;
        QTreeWidget *dataTable;

        // progress update side
        // headings
        QLabel *itLabel, *cpLabel, *wLabel, *tLabel, *sumLabel;
        // current
        QLabel *citLabel, *ccpLabel, *cwLabel, *ctLabel, *csumLabel;
        // best so far
        QLabel *bitLabel, *bcpLabel, *bwLabel, *btLabel, *bsumLabel;

        // visualise
        QWidget *solverDisplay; // need to create a custom widget for this

        QPushButton *solve, *close;

        Context *context;
        QList<RideItem*> items;

    private slots:

        void selectAll();
        void solveClicked();
        void closeClicked();
};

