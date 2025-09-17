import { MercadoPagoConfig, Payment } from "mercadopago";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";
dotenv.config({ path: "./api.env" });

const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 5000 },
});

const payment = new Payment(client);

export async function processPayment(paymentData) {
  try {
    const REAL_TRANSACTION_AMOUNT = 5;
    const DESCRIPTION = "Análise detalhada de currículo - ReprovaCV";

    const fakeAmount = paymentData.transaction_amount; 
    if(fakeAmount != REAL_TRANSACTION_AMOUNT){
      console.log("💰 Valor enviado pelo frontend (não confiável):", fakeAmount);
    }

    const response = await payment.create({
      body: {
        transaction_amount: REAL_TRANSACTION_AMOUNT, // valor seguro
        token: paymentData.token,
        description: DESCRIPTION, // descrição segura
        installments: paymentData.installments || 1, // pode aceitar do frontend
        payment_method_id: paymentData.payment_method_id,
        issuer_id: paymentData.issuer_id,
        payer: {
          email: paymentData.payer.email,
          identification: {
            type: paymentData.payer.identification.type,
            number: paymentData.payer.identification.number,
          },
        },
      },
      requestOptions: { idempotencyKey: uuidv4() }
    });

    return response;
  } catch (error) {
    console.error("Erro ao processar pagamento:", error);
    throw error;
  }
}