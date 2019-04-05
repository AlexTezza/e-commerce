<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Model;
use Hcode\Mailer;

class User extends Model {

    const SESSION = "User";
    const SECRET = "Ecommerce_Secret";
    const SECRET_IV = "Ecommerce_Secret";
    const USER_ERROR = "USER_ERROR";

    public static function getFromSession($inadmin = true) {

        $user = new User();

        if (isset($_SESSION[User::SESSION]) && (int)$_SESSION[User::SESSION]['iduser'] > 0) {
            $user->setData($_SESSION[User::SESSION]);
        }

        return $user;
    }

    public static function checkLogin($inadmin = true) {
        if (
            !isset($_SESSION[User::SESSION])
            ||
            !$_SESSION[User::SESSION]
            ||
            !(int)$_SESSION[User::SESSION]["iduser"] > 0
        ) {
            // Nâo esta logado
            return false;
        } else if ($inadmin === true && (bool)$_SESSION[User::SESSION]['inadmin'] === true) {
            return true;
        } else if ($inadmin === false) {
            return true;
        } else {
            return false;
        } 
    }

    public static function login($login, $password) {

        $sql = new Sql();

        $results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :LOGIN", array(
            ":LOGIN"=>$login
        ));

        if (count($results) === 0) {
            throw new \Exception("Usuário inesistente ou senha inválida.");
        }

        $data = $results[0];

        if (password_verify($password, $data["despassword"]) === true) {
            $user = new User();

            $data['desperson'] = utf8_encode($data['desperson']);

            $user->setData($data);

            $_SESSION[User::SESSION] = $user->getValues();

            return $user;
        } else {
            throw new \Exception("Usuário inesistente ou senha inválida.");
        }
    }

    public static function verifyLogin($inadmin = true) {
        if (!User::checkLogin($inadmin)) {
            if ($inadmin) {
                header("Location: /admin/login");
            } else {
                header("Location: /login");
            }
            exit;
        }
    }

    public static function logout() {
        $_SESSION[User::SESSION] = NULL;
    }

    public static function listAll() {
        $sql = new Sql();
        return $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) ORDER BY b.desperson");
    }

    public function save() {
        $sql = new Sql();
        $result = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)",
            array(
                ":desperson"=>utf8_decode($this->getdesperson()),
                ":deslogin"=>$this->getdeslogin(),
                ":despassword"=>User::getPasswordHash($this->getdespassword()),
                ":desemail"=>$this->getdesemail(),
                ":nrphone"=>$this->getnrphone(),
                ":inadmin"=>$this->getinadmin()
        ));

        $this->setData($result[0]);
    }

    public function get($iduser) {
        $sql = new Sql();

        $result = $sql->select("SELECT * FROM tb_users a INNER JOIN tb_persons b USING(idperson) WHERE a.iduser = :IDUSER",
            array(
                ":IDUSER"=>$iduser
        ));

        $data = $result[0];

        $data['desperson'] = utf8_encode($data['desperson']);

        $this->setData($data);
    }

    public function update() {
        $sql = new Sql();
        $result = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)",
            array(
                ":iduser"=>$this->getiduser(),
                ":desperson"=>uft8_decode($this->getdesperson()),
                ":deslogin"=>$this->getdeslogin(),
                ":despassword"=>User::getPasswordHash($this->getdespassword()),
                ":desemail"=>$this->getdesemail(),
                ":nrphone"=>$this->getnrphone(),
                ":inadmin"=>$this->getinadmin()
        ));

        $this->setData($result[0]);
    }

    public function delete() {
        $sql = new Sql();

        $sql->query("CALL sp_users_delete(:iduser)", array(
            ":iduser"=>$this->getiduser()
        ));
    }

    public static function getForgot($email) {

        $sql = new Sql();

        $results = $sql->select("
            SELECT *
            FROM tb_persons a
            INNER JOIN tb_users b USING(idperson)
            WHERE a.desemail = :EMAIL;
        ", array(
            ":EMAIL"=>$email
        ));

        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.");
        } else {

            $data = $results[0];

            $resultProc = $sql->select("CALL sp_userspasswordsrecoveries_create(:IDUSER, :DESIP)", array(
                ":IDUSER"=>$data["iduser"],
                ":DESIP"=>$_SERVER["REMOTE_ADDR"]
            ));

            if (count($resultProc) === 0) {
                throw new \Exception("Não foi possível recuperar a senha.");
            } else {
                $dataRecovery = $resultProc[0];

                $code = base64_encode(openssl_encrypt(
                    $dataRecovery["idrecovery"],
                    'AES-128-CBC',
                    User::SECRET,
                    0,
                    User::SECRET_IV
                ));

                $link = "http://www.hcodecommerce.com.br/admin/forgot/reset?code=$code";

                $mailer = new Mailer($data["desemail"], $data["desperson"], "Redefiner senha de Tezza Store", "forgot", array(
                    "name"=>$data["desperson"],
                    "link"=>$link
                ));

                $mailer->send();

                return $data;
            }
        }
    }

    public static function validForgotDecrypt($code) {

        $idrecovery = openssl_decrypt(
            base64_decode($code),
            'AES-128-CBC',
            User::SECRET,
            0,
            User::SECRET_IV
        );

        $sql = new Sql();

        $results = $sql->select("
                SELECT * 
                FROM tb_userspasswordsrecoveries a
                    INNER JOIN tb_users b USING(iduser)
                    INNER JOIN tb_persons c USING(idperson)
                WHERE 
                    a.idrecovery = :idrecovery
                    AND a.dtrecovery IS NULL
                    AND DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW();
        ", array(
            ":idrecovery"=>$idrecovery
        ));

        if (count($results) === 0) {
            throw new \Exception("Não foi possível recuperar a senha.", 1);
        } else {
            return $results[0];
        }
    }

    public static function setForgotUserd($idrecovery) {
        $sql = new Sql();

        $sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(
            ":idrecovery"=>$idrecovery
        ));
    }

    public function setPassword($password) {
        $sql = new Sql();

        $sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
            ":password"=>$password,
            ":iduser"=>$this->getiduser()
        ));
    }

    public static function setMsgError($msg) {
        $_SESSION[User::USER_ERROR] = $msg;
    }

    public static function getMsgError() {

        $msg = (isset($_SESSION[User::USER_ERROR])) ? $_SESSION[User::USER_ERROR] : "";

        User::clearMsgError();

        return $msg;
    }

    public static function clearMsgError() {
        $_SESSION[User::USER_ERROR] = NULL;
    }

    public static function getPasswordHash($password) {
        return password_hash($password, PASSWORD_DEFAULT, [
            'cost'=>12
        ]);
    }

}

?>