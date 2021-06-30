#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "cryptopputil.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();


    void testRSA();

private slots:

    void on_SignBtn_clicked();

    void on_verifyBtn_clicked();

    void on_autoPubPriBtn_clicked();

private:
    Ui::MainWindow *ui;
    CryptoPP::AutoSeededRandomPool mRng;
};
#endif // MAINWINDOW_H
