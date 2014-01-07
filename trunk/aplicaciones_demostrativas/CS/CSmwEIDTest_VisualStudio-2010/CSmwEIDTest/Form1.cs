using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace CSmwEIDTest
{
    public partial class Form1 : Form
    {
        PKCS11Controller m_Controller;
        public Form1()
        {
            InitializeComponent();
            m_Controller = new PKCS11Controller("beidpkcs11.dll");
            m_Controller.SetIssuerCertificate("CA SINPE - PERSONA FISICA.cer");
        }

        private void Form1_Shown(object sender, EventArgs e)
        {
            List<string> readers = m_Controller.GetReadersList();
            if (readers.Count > 0)
            {
                cbxCardReaders.Items.Add("[Selecccione un Card Reader]");
                cbxCardReaders.SelectedIndex = 0;
                cbxCardReaders.Items.AddRange(readers.ToArray());
                statusStrip1.Items[0].Text = "Card Readers Cargados.";
                groupBox1.Enabled = true;
            }
            else
            {
                statusStrip1.Items[0].Text = "No se detectaron Card Readers.";
            }
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            btnLogin.Enabled = false;
            groupBox2.Enabled = groupBox3.Enabled = false;
            tbCardInfo.Text = string.Empty;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                errorProvider1.Clear();
                if (cbxCardReaders.SelectedIndex != 0)
                {
                    int slotIndex = (cbxCardReaders.SelectedIndex - 1);
                    statusStrip1.Items[0].Text = "Slot Seleccionado[" + slotIndex + "]";
                    if (tbTokenPassword.Text.Trim() == string.Empty)
                    {
                        string msg = "El Número de PIN es requerido";
                        statusStrip1.Items[0].Text = msg;
                        errorProvider1.SetError(tbTokenPassword, msg);
                        return;
                    }
                    if (tbNumeroTarjeta.Text.Trim() == string.Empty)
                    {
                        string msg = "El Número de Tarjeta es requerido";
                        statusStrip1.Items[0].Text = msg;
                        errorProvider1.SetError(tbNumeroTarjeta, msg);
                        return;
                    }

                    if (tbNumeroTarjeta.Text.Trim() == string.Empty)
                    {
                        string msg = "Debe proveer un Número de Tarjeta";
                        statusStrip1.Items[0].Text = msg;
                        errorProvider1.SetError(tbNumeroTarjeta, msg);
                        return;
                    }

                    if (!m_Controller.Login(slotIndex, tbTokenPassword.Text.Trim()))
                    {
                        string msg = "PIN Incorrecto";
                        statusStrip1.Items[0].Text = msg;
                        errorProvider1.SetError(tbTokenPassword, msg);
                        return;
                    }
                    else
                    {
                        string msg = "PIN Correcto";
                        statusStrip1.Items[0].Text = msg;

                        if (!m_Controller.NumeroTarjetaValida(slotIndex, tbNumeroTarjeta.Text.Trim()))
                        {
                            msg = "Debe proveer un Número de Tarjeta Válido";
                            statusStrip1.Items[0].Text = msg;
                            errorProvider1.SetError(tbNumeroTarjeta, msg);
                            return;
                        }
                        groupBox2.Enabled = true;
                        tbCardInfo.Text = m_Controller.GetTokenInfo(slotIndex);
                    }

                }
                else
                {
                    string msg = "Debe Seleccionar un Card Reader";
                    statusStrip1.Items[0].Text = msg;
                    errorProvider1.SetError(cbxCardReaders, msg);
                }
            }
            finally
            {
                btnLogin.Enabled = true;
                this.Cursor = Cursors.Default;
            }
        }

        private void cbxCardReaders_SelectedIndexChanged(object sender, EventArgs e)
        {
            errorProvider1.Clear();
            groupBox2.Enabled = groupBox3.Enabled = false;
            statusStrip1.Items[0].Text = "Card Readers Cargados.";
            tbTokenPassword.Text = tbNumeroTarjeta.Text = tbCardInfo.Text = tbTextFirmado.Text =  string.Empty;
        }

        private void btnFirmar_Click(object sender, EventArgs e)
        {
            errorProvider1.Clear();
            btnFirmar.Enabled = false;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                if (cbxCardReaders.SelectedIndex != 0)
                {
                    byte[] encryptedData = null;
                    int slotIndex = (cbxCardReaders.SelectedIndex - 1);
                    if (!m_Controller.Firmar(slotIndex, tbTokenPassword.Text.Trim(),
                        System.Text.Encoding.UTF8.GetBytes(tbTextoAFirmar.Text), out encryptedData))
                    {
                        string msg = "PIN Incorrecto";
                        statusStrip1.Items[0].Text = msg;
                        errorProvider1.SetError(tbTokenPassword, msg);
                        return;
                    }
                    else
                    {
                        tbTextFirmado.Text = System.Text.Encoding.UTF8.GetString(encryptedData);
                        statusStrip1.Items[0].Text = "Texto Firmado Correctamente";
                    }
                }
                else
                {
                    string msg = "Debe Seleccionar un Card Reader";
                    statusStrip1.Items[0].Text = msg;
                    errorProvider1.SetError(cbxCardReaders, msg);
                }
            }
            finally
            {
                btnFirmar.Enabled = true;
                this.Cursor = Cursors.Default;
            }
        }

        private void btnAutenticar_Click(object sender, EventArgs e)
        {
            errorProvider1.Clear();
            btnAutenticar.Enabled = false;
            this.Cursor = Cursors.WaitCursor;
            try
            {
                if (cbxCardReaders.SelectedIndex != 0)
                {
                    string error = string.Empty;
                    int slotIndex = (cbxCardReaders.SelectedIndex - 1);
                    if (!m_Controller.Autenticar(slotIndex, tbTokenPassword.Text.Trim(), out error))
                    {
                        statusStrip1.Items[0].Text = error;
                        errorProvider1.SetError(btnAutenticar, error);
                        return;
                    }
                    else
                    {
                        string msg = "Autenticación Exitosa";
                        statusStrip1.Items[0].Text = msg;
                        groupBox3.Enabled = true;
                    }
                }
                else
                {
                    string msg = "Debe Seleccionar un Card Reader";
                    statusStrip1.Items[0].Text = msg;
                    errorProvider1.SetError(cbxCardReaders, msg);
                }
            }
            finally
            {
                btnAutenticar.Enabled = true;
                this.Cursor = Cursors.Default;
            }
        }

        private void btnAutenticar_MouseDown(object sender, MouseEventArgs e)
        {
            statusStrip1.Items[0].Text = "Autenticando con servidor OCSP";
        }

        private void btnFirmar_MouseDown(object sender, MouseEventArgs e)
        {
            statusStrip1.Items[0].Text = "Firmando";
        }

        private void btnLogin_MouseDown(object sender, MouseEventArgs e)
        {
            statusStrip1.Items[0].Text = "Validando";
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (checkBox1.Checked)
            {
                tbTokenPassword.PasswordChar = (char)0;
            }
            else
            {
                tbTokenPassword.PasswordChar = '*';
            }

        }
    }
}
