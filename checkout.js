import { MercadoPagoConfig, Preference } from "mercadopago";

const client = new MercadoPagoConfig({
  accessToken: process.env.MP_ACCESS_TOKEN,
  options: { timeout: 5000 },
});

const preference = new Preference(client);

export async function createPreference() {
  const body = {
    items: [
      {
        id: "1",
        title: "Compra teste",
        currency_id: "BRL",
        quantity: 1,
        unit_price: 5,
      },
    ],
    payer: {
      email: "abigail-andersdatter@tuamaeaquelaursa.com",
    },
    back_urls: {
      success: "https://reprovacurriculo.com.br/sucesso",
      failure: "https://reprovacurriculo.com.br/reprova",
      pending: "https://reprovacurriculo.com.br/reprova",
    },
    auto_return: "approved",
  };

  try {
    const response = await preference.create({ body });
    return response.body.init_point; // ⚠️ precisa ser response.body.init_point
  } catch (error) {
    console.error("Erro ao criar preferência:", error);
    throw error;
  }
}
