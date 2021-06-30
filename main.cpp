#include "mainwindow.h"

/*#include "cryptopp/include/md5.h"
#include "cryptopp/include/filters.h"
#include "cryptopp/include/hex.h"*/
#include <QApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

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

    CryptoPP::AutoSeededRandomPool rng;

    // Message
    std::string message = "clever";


    CryptoPP::ByteQueue Privatequeue;
    CryptoPP::HexDecoder encoder(new CryptoPP::Redirector(Privatequeue));
    // Signer object
    CryptoPP::Weak::RSASSA_PKCS1v15_MD5_Signer signer;
    std::string dek = QString(privateKeydecBase64.toHex()).toStdString();
    //std::cout<<dek.size()<<"           dek                     "<<dek<<std::endl;
    encoder.Put((const unsigned char*)dek.data(), dek.size());
    encoder.MessageEnd();
    signer.AccessKey().Load(Privatequeue);


    // Sign message
    std::string signedMessage = "";
    CryptoPP::StringSource s1(message, true, new CryptoPP::SignerFilter(rng, signer, new CryptoPP::HexEncoder(new CryptoPP::StringSink(signedMessage))));

    // Verifier object
    CryptoPP::ByteQueue Publicqueue;
    CryptoPP::Weak::RSASSA_PKCS1v15_MD5_Verifier verifier;
    CryptoPP::HexDecoder decoder(new CryptoPP::Redirector(Publicqueue));
    std::string dec = QString(publicKeydecBase64.toHex()).toStdString();
    //std::cout<<"dec"<<dec<<std::endl;
    decoder.Put((const unsigned char*)dec.data(), dec.size());
    decoder.MessageEnd();
    verifier.AccessKey().Load(Publicqueue);

    CryptoPP::StringSource signatureFile( signedMessage, true, new CryptoPP::HexDecoder);
    if (signatureFile.MaxRetrievable() != verifier.SignatureLength())
    { throw std::string( "Signature Size Problem" ); }

    CryptoPP::SecByteBlock signature1(verifier.SignatureLength());
    signatureFile.Get(signature1, signature1.size());

    // Verify
    CryptoPP::SignatureVerificationFilter *verifierFilter = new CryptoPP::SignatureVerificationFilter(verifier);
    verifierFilter->Put(signature1, verifier.SignatureLength());
    CryptoPP::StringSource s(message, true, verifierFilter);

    // Result
    qDebug()<<"verifierFilter->GetLastResult()"<<verifierFilter->GetLastResult()<<endl;

    // Result
    if(true == verifierFilter->GetLastResult()) {
        qDebug() << "Signature on message verified" << endl;
    } else {
        qDebug() << "Message verification failed" << endl;
    }
    MainWindow w;
    w.show();
    return a.exec();
}
