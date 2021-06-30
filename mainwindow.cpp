#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "pssr.h"
using CryptoPP::PSS;

#include "sha.h"
using CryptoPP::SHA1;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "filters.h"
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::Integer;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "SecBlock.h"
using CryptoPP::SecByteBlock;

#include <string>
using std::string;

#include <iostream>
using std::cout;
using std::endl;

#include <sha.h>
using CryptoPP::SHA1;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <queue.h>
using CryptoPP::ByteQueue;

#include <integer.h>
using CryptoPP::Integer;

#include <base64.h>
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;


void Save(const string& filename, const BufferedTransformation& bt)
{
    FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveBase64(const string& filename, const BufferedTransformation& bt)
{
    Base64Encoder encoder;

    bt.CopyTo(encoder);
    encoder.MessageEnd();

    Save(filename, encoder);
}

void SavePrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void SavePublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}

void SaveBase64PrivateKey(const string& filename, const PrivateKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string& filename, const PublicKey& key)
{
    ByteQueue queue;
    key.Save(queue);

    SaveBase64(filename, queue);
}

bool Load(const string& filename, BufferedTransformation& bt)
{
    bool ret = true;
    try {
        FileSource file(filename.c_str(), true /*pumpAll*/);

        file.TransferTo(bt);
        bt.MessageEnd();
    } catch (CryptoPP::Exception& e) {
        ret = false;
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return ret;

}

bool LoadPrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;

    bool ret = Load(filename, queue);
    key.Load(queue);
    return ret;
}

bool LoadPublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;

    bool ret = Load(filename, queue);
    key.Load(queue);
    return ret;
}



bool LoadBase64(const string& filename, BufferedTransformation& bt)
{
    Base64Decoder decoder;
    bool ret = Load(filename,decoder);

    decoder.CopyTo(bt);
    bt.MessageEnd();
    return ret;
}

bool  LoadBase64PrivateKey(const string& filename, PrivateKey& key)
{
    ByteQueue queue;

    bool ret = LoadBase64(filename, queue);
    key.Load(queue);
    return ret;
}

bool LoadBase64PublicKey(const string& filename, PublicKey& key)
{
    ByteQueue queue;

    bool ret = LoadBase64(filename, queue);
    key.Load(queue);
    return ret;
}


void MainWindow::testRSA()
{
    try
    {
        ////////////////////////////////////////////////
        // 伪随机数生成器
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 2048 );

        ///////////////////////////////////////
        const Integer& n = parameters.GetModulus();
        const Integer& p = parameters.GetPrime1();
        const Integer& q = parameters.GetPrime2();
        const Integer& d = parameters.GetPrivateExponent();
        const Integer& e = parameters.GetPublicExponent();


        cout << "RSA Parameters:" << endl;
        cout << " n: " << std::hex << n << endl;    //n=p*q
        cout << " p: " << std::hex << p << endl;    //p
        cout << " q: " << std::hex << q << endl;    //q
        cout << " d: " << std::hex << d << endl;
        cout << " e: " << std::hex << e << endl;    //e默认是17,原因不明
        cout << endl;

        // 生成私钥和公钥
        RSA::PrivateKey privateKey( parameters );       //(n,e)
        RSA::PublicKey  publicKey( parameters );        //(n,d)
        ////////////////////////////////////////////////
        //保存base64 key到文件
        SaveBase64PrivateKey("rsa-base64-private.key", privateKey);
        SaveBase64PublicKey("rsa-base64-public.key", publicKey);

        // 发送消息Message
        std::string message = "Hello,world!";



        // 利用私钥进行签名Signer object
        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);


        // 输出签名 Sign message
        std::string signedMessage = "";
        CryptoPP::StringSource s1(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signedMessage))));



        // 利用公钥对签名进行校验 Verifier object
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

        CryptoPP::StringSource signatureFile( signedMessage, true, new CryptoPP::HexDecoder);
        if (signatureFile.MaxRetrievable() != verifier.SignatureLength())
        { throw std::string( "Signature Size Problem" ); }

        CryptoPP::SecByteBlock signature1(verifier.SignatureLength());
        signatureFile.Get(signature1, signature1.size());

        // Verify
        CryptoPP::SignatureVerificationFilter *verifierFilter = new CryptoPP::SignatureVerificationFilter(verifier);
        verifierFilter->Put(signature1, verifier.SignatureLength());
        CryptoPP::StringSource s(message, true, verifierFilter);

        //校验结果 Result
        cout<<"verifierFilter->GetLastResult()"<<verifierFilter->GetLastResult()<<endl;

        //校验结果 Result
        if(true == verifierFilter->GetLastResult()) {
            cout << "Signature on message verified" << endl;
        } else {
            cout << "Message verification failed" << endl;
        }
    } //SignatureVerificationFilter::THROW_EXCEPTION 验证失败抛出异常

    catch( CryptoPP::Exception& e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_SignBtn_clicked()
{
    try{
        if( ui->plainTextEdit->toPlainText().isEmpty() ) return;
        cout<<"string is not empty  "<<ui->plainTextEdit->toPlainText().toStdString()<<endl;
        QByteArray privateKeydecBase64 = QByteArray::fromBase64(
                    QString("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCvYMbiPk2DHUTu \
                            vN7qDpXbjtBjnuxMHK6le8J3vYSmqv1q4a++V1Qdeh9WkJ58IqIIkDM28b2eBXBz \
                            aSzbDSh8xmGjok+6+YVgyR5SK5arP3b8K5zclXczC2+C/UgoEzM4m24g1HN1wNXE \
                            NaYC9jrAO0ui2NICijLzN7jQszWcQ2yx97Ynudu4wa7pvV0W2JBNqo3GwO06oUM8 \
                            YZV/Q8iipwCxN3bqX9htbcDOzkQ3zz2MZgIlVTLWHaEU1Ts859PIwwji013RytD2 \
                            CQan56roVUs9YN9Q+6wlRJD+4rL9LVa8Xq4ssNwYQr9QrCknfZ/jExFbRn5Nmpas \
                            9i0DRxhHAgMBAAECggEAZ4N9oCgZ5BuwhiEgiZHWTeM7iLFS05HSW4Zyv+4yj5U5 \
                            Qo63BmfRFBzyxktR3/8pGFjUgcepnc2kE9quSRS5IvyMwOKaoMeKPBg5N1LW+Xja \
                            J/kt+tyVoKFNTklk/5JllzHWjLYY+BW7lrX7qJ/hCXl2KUZEno8nh3sKMNS1/ear \
                            YTPH7cbq1tCRu7JMqsDf3kjpdHaq4enpyIZMrSrwuR7hjWBfbxxnZx35asiRjv4F \
                            HnOn9R7KszQjQ2SINNWiT2zAUBguiyDFl+60ZNCeeX6Iei4ax9HNg/iF5jHPht9j \
                            bpbm2/Z0RHkXr1zmn4eBv9Z6dO9B/pwveuo5rl6s0QKBgQDiaSXN2uo9V1ddjwGm \
                            f6r2tRUh1kzjDOEVscZgHHHXSyZIozzrNM5j2/qOTSsnLvCBPXln6vW2olN10mUJ \
                            xmO5joQBEdG0FD7LAgdz7JeMnzPimo46WLfvGs1gxE3WaRct55bpomA/qb3Ovd9P \
                            G1RagOx2WKwki6yatzKzHU7aCwKBgQDGTERTh2N2UQhrdE4kY/h3TokdH0uOBRxK \
                            RjAsWWlnjaQlyy0rJ7RUQw53gFcR0DV/Z96EOXRppTD78Yby4wAaq6ja6fQNVWjd \
                            AlbCPUWWSJ7wvQotRqUlxELJk/DGcXEJaKOSELFQDZhotvvhO1xC6Z7/2M4caLDA \
                            1xWMqchcNQKBgAfj+jlOY9N3c8gC79/Jmz+11+KyAUP4cu+6nltDIoSKTe9CISFh \
                            WcAJLpY/Aj3/WMpoRg7lFWMkDRySFIteqqMQ4HDZGiHYgse4bmIP4Mg51CkVkdde \
                            uCpRGM9CiCPsza3/4DaMPiZ51++Ylmu/XBU7YQJO3ND5PS63K8EqSFE5AoGAKRoF \
                            z4pwg0WoiR1CVSijh5cvtGmYL4e/pWWG9qpRvrUNIQhMBHXmWtDLXtmrMnYFoLLW \
                            3HFMP9mNnasiXZXPn7eU+Esl2t2pLqYddYVdtxi2WQ/V3CyYbouPjFitv3QkCd82 \
                            iEANgJpQzOOgsb6sEPJ7kmxNzHWmrVHnlZBbh0ECgYBgcQydlp/HqJYp09BlvcQZ \
                            GjL6yv1/tx9J2p0QFYrpb5zSWas0Bx4cpHIve0M64QYXFjSzoH/88pc7mkzOfSK3 \
                            Slau227c+TQBkIsWgcbvydYbcTBy8i2pOoUkM+EJV8i/ja4t2aBNOV+l81I3/ZrY \
                            3t0osnDRfJ0INvlDx9dPfQ==").toLatin1());

        QByteArray publicKeydecBase64 = QByteArray::fromBase64(
                    QString("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr2DG4j5Ngx1E7rze6g6V \
                            247QY57sTByupXvCd72Epqr9auGvvldUHXofVpCefCKiCJAzNvG9ngVwc2ks2w0o \
                            fMZho6JPuvmFYMkeUiuWqz92/Cuc3JV3Mwtvgv1IKBMzOJtuINRzdcDVxDWmAvY6 \
                            wDtLotjSAooy8ze40LM1nENssfe2J7nbuMGu6b1dFtiQTaqNxsDtOqFDPGGVf0PI \
                            oqcAsTd26l/YbW3Azs5EN889jGYCJVUy1h2hFNU7POfTyMMI4tNd0crQ9gkGp+eq \
                            6FVLPWDfUPusJUSQ/uKy/S1WvF6uLLDcGEK/UKwpJ32f4xMRW0Z+TZqWrPYtA0cY \
                            RwIDAQAB").toLatin1());

        // 发送消息  message need to send
        std::string message = ui->plainTextEdit->toPlainText().toStdString();


        // 读取私钥 read private Key from file
        RSA::PrivateKey privateKey;//(n,e)
        bool ret = LoadBase64PrivateKey("rsa-base64-private.key" , privateKey);
        if( !ret ) { cout << " no rsa-base64-private.key file"<<endl;return;}

        // 利用私钥进行签名 signer object with private key
        CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(privateKey);


        // 输出签名 output sign message
        std::string signedMessage = "";
        CryptoPP::StringSource s1(message, true, new CryptoPP::SignerFilter(mRng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signedMessage))));


        cout<< " signedMessage "<<signedMessage << endl;

        // 签名 std::string to base64
        QByteArray ba;
        ba=QString::fromStdString(signedMessage).toLatin1();           //QByteArray
        ba=ba.toBase64();          //Base64
        char * cx=ba.data();       //char *
        QString b64qs1=QString(cx);//QString
        ui->plainTextEdit_2->setPlainText(b64qs1);

    } //SignatureVerificationFilter::THROW_EXCEPTION 验证失败抛出异常

    catch( CryptoPP::Exception& e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}


void MainWindow::on_verifyBtn_clicked()
{
    try{
        // 读取公钥 read public Key from file
        RSA::PublicKey  publicKey;        //(n,d)
        // 利用公钥对签名进行校验 verifier object
        bool ret = LoadBase64PublicKey("rsa-base64-public.key" , publicKey);
        if( !ret ) { cout << " no rsa-base64-private.key file"<<endl;return;}
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

        // 签名 base64 to std::string
        QString signmessage = QString(QByteArray::fromBase64(
                    QString(ui->plainTextEdit_2->toPlainText()).toLatin1()));
        cout<< " signmesage "<<signmessage.toStdString() << endl;

        CryptoPP::StringSource signatureFile( signmessage.toStdString() , true, new CryptoPP::HexDecoder);
        if (signatureFile.MaxRetrievable() != verifier.SignatureLength())
        { throw std::string( "Signature Size Problem" ); }

        CryptoPP::SecByteBlock signature1(verifier.SignatureLength());
        signatureFile.Get(signature1, signature1.size());

        //与原来的传输消息验证 verify with original transmission message
        CryptoPP::SignatureVerificationFilter *verifierFilter = new CryptoPP::SignatureVerificationFilter(verifier);
        verifierFilter->Put(signature1, verifier.SignatureLength());
        CryptoPP::StringSource s(ui->plainTextEdit->toPlainText().toStdString(), true, verifierFilter);

        //校验结果 verify Result
        cout<<"verifierFilter->GetLastResult()"<<verifierFilter->GetLastResult()<<endl;

        //校验结果 verify Result
        if(true == verifierFilter->GetLastResult()) {
            cout << "Signature on message verified" << endl;
            ui->resultLab->setText("Signature on message verified");
        } else {
            cout << "Message verification failed" << endl;
            ui->resultLab->setText("Message verification failed");
        }
    } //SignatureVerificationFilter::THROW_EXCEPTION 验证失败抛出异常

    catch( CryptoPP::Exception& e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}


void MainWindow::on_autoPubPriBtn_clicked()
{
    ////////////////////////////////////////////////
    // 伪随机数生成器 pseudo-random number generator


    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize( mRng, 2048 );

    ///////////////////////////////////////
    const Integer& n = parameters.GetModulus();
    const Integer& p = parameters.GetPrime1();
    const Integer& q = parameters.GetPrime2();
    const Integer& d = parameters.GetPrivateExponent();
    const Integer& e = parameters.GetPublicExponent();


    cout << "RSA Parameters:" << endl;
    cout << " n: " << std::hex << n << endl;    //n=p*q
    cout << " p: " << std::hex << p << endl;    //p
    cout << " q: " << std::hex << q << endl;    //q
    cout << " d: " << std::hex << d << endl;
    cout << " e: " << std::hex << e << endl;    //e = 17
    cout << endl;

    // 生成私钥和公钥 create private key and public key
    RSA::PrivateKey privateKey( parameters );       //(n,e)
    RSA::PublicKey  publicKey( parameters );        //(n,d)
    ////////////////////////////////////////////////
    //保存base64 key到文件 save base64 key to the file
    SaveBase64PrivateKey("rsa-base64-private.key", privateKey);
    SaveBase64PublicKey("rsa-base64-public.key", publicKey);

    QFile priFile("rsa-base64-private.key");

    //打开文件 open file
    bool priisOK = priFile.open(QIODevice::ReadOnly);
    if(priisOK == true){
        QByteArray array;
        while (priFile.atEnd() == false) {
            //读一行 read per line
            array +=  priFile.readLine();
            ui->plainTextEdit_3->setPlainText(array);
        }

    }
    priFile.close();

    QFile pubFile("rsa-base64-public.key");

    //打开文件 open file
    bool pubisOK = pubFile.open(QIODevice::ReadOnly);
    if(pubisOK == true){
        QByteArray array;
        while (pubFile.atEnd() == false) {
            //读一行 read per line
            array +=  pubFile.readLine();
            ui->plainTextEdit_4->setPlainText(array);
        }

    }
    pubFile.close();
}

