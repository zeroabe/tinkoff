package tinkoff

type GetStateRequest struct {
	BaseRequest

	PaymentID string `json:"PaymentId"`    // Идентификатор платежа в системе банка. По офф. документации это number(20), но фактически значение передается в виде строки
	ClientIP  string `json:"IP,omitempty"` // IP-адрес покупателя
}

func (i *GetStateRequest) GetValuesForToken() map[string]string {
	return map[string]string{
		"IP":        i.ClientIP,
		"PaymentId": i.PaymentID,
	}
}

type GetStateResponse struct {
	BaseResponse
	OrderID   string `json:"OrderId"`   // Номер заказа в системе Продавца
	Status    string `json:"Status"`    // Статус платежа
	PaymentID string `json:"PaymentId"` // Уникальный идентификатор транзакции в системе Банка
}

func (c *client) GetState(request *GetStateRequest) (*GetStateResponse, error) {
	response, err := c.PostRequest("/GetState", request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	var res GetStateResponse
	err = c.decodeResponse(response, &res)
	if err != nil {
		return nil, err
	}

	return &res, res.Error()
}
