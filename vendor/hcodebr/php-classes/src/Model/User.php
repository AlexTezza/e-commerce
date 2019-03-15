<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Model;
use Hcode\Mailer;

class User extends Model {

    const SESSION = "User";
    const SECRET = "Ecommerce_Secret";

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
            $user->setData($data);

            $_SESSION[User::SESSION] = $user->getValues();

            return $user;
        } else {
            throw new \Exception("Usuário inesistente ou senha inválida.");
        }
    }

    public static function verifyLogin($inadmin = true) {
        if (!isset($_SESSION[User::SESSION])
            || !$_SESSION[User::SESSION]
            || !$_SESSION[User::SESSION]["iduser"] > 0
            || (bool)$_SESSION[User::SESSION]["inadmin"] !== $inadmin) {

            header("Location: /admin/login");
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
                ":desperson"=>$this->getdesperson(),
                ":deslogin"=>$this->getdeslogin(),
                ":despassword"=>$this->getdespassword(),
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

        $this->setData($result[0]);
    }

    public function update() {
        $sql = new Sql();
        $result = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)",
            array(
                ":iduser"=>$this->getiduser(),
                ":desperson"=>$this->getdesperson(),
                ":deslogin"=>$this->getdeslogin(),
                ":despassword"=>$this->getdespassword(),
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

                define('SECRET_IV', pack('a16', 'senha'));
                define('SECRET', pack('a16', 'senha'));

                $dataS = [
                    "nome" => "Hcode"
                ];

                $code = base64_encode(openssl_encrypt(
                    json_encode($dataS),
                    'AES-128-CBC',
                    SECRET,
                    0,
                    SECRET_IV
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

}

?>