package edge

import (
	"net/http"
	"strings"
)

type I18nStrings struct {
	ConnectionStatus string `json:"connection_status"`
	YourClient       string `json:"your_client"`
	Network          string `json:"network"`
	WebServer        string `json:"web_server"`
	Working          string `json:"working"`
	Unknown          string `json:"unknown"`
	ClientError      string `json:"client_error"`
	ServerError      string `json:"server_error"`
	WhatHappened     string `json:"what_happened"`
	WhatCanIDo       string `json:"what_can_id_o"`
	Description      string `json:"description"`
	WhatToDo         string `json:"what_to_do"`
	ClientCardState  string `json:"client_card_state"`
	ClientCardText   string `json:"client_card_text"`
	NetworkCardState string `json:"network_card_state"`
	NetworkCardText  string `json:"network_card_text"`
	ServerCardState  string `json:"server_card_state"`
	ServerCardText   string `json:"server_card_text"`
	Host             string `json:"host"`
	OriginalURI      string `json:"original_uri"`
	TraceID          string `json:"trace_id"`
	RequestID        string `json:"request_id"`
	EdgeID           string `json:"edge_id"`
	ContactSupport   string `json:"contact_support"`
}

func getLanguage(r *http.Request) string {
	accept := r.Header.Get("Accept-Language")
	if accept == "" {
		return "en"
	}
	parts := strings.Split(accept, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		lang = strings.ToLower(lang)
		if strings.HasPrefix(lang, "zh") {
			return "zh"
		}
		if strings.HasPrefix(lang, "en") {
			return "en"
		}
		if strings.HasPrefix(lang, "ar") {
			return "ar"
		}
		if strings.HasPrefix(lang, "fr") {
			return "fr"
		}
		if strings.HasPrefix(lang, "ru") {
			return "ru"
		}
		if strings.HasPrefix(lang, "es") {
			return "es"
		}
	}
	return "en"
}

func getI18n(lang string, status int) I18nStrings {
	var clientState, clientText string
	var networkState, networkText string
	var serverState, serverText string

	workingText := translate(lang, "Working")
	unknownText := translate(lang, "Unknown")

	if status >= 400 && status <= 499 {
		clientState = "error"
		clientText = translate(lang, "ClientError")
		networkState = "ok"
		networkText = workingText
		serverState = "ok"
		serverText = workingText
	} else if status >= 500 && status <= 599 {
		clientState = "ok"
		clientText = workingText
		networkState = "ok"
		networkText = workingText
		serverState = "error"
		serverText = translate(lang, "ServerError")
	} else if status >= 100 && status < 400 {
		clientState = "ok"
		clientText = workingText
		networkState = "ok"
		networkText = workingText
		serverState = "ok"
		serverText = workingText
	} else {
		clientState = "warning"
		clientText = unknownText
		networkState = "ok"
		networkText = workingText
		serverState = "warning"
		serverText = unknownText
	}

	return I18nStrings{
		ConnectionStatus: translate(lang, "ConnectionStatus"),
		YourClient:       translate(lang, "YourClient"),
		Network:          translate(lang, "Network"),
		WebServer:        translate(lang, "WebServer"),
		Working:          workingText,
		Unknown:          unknownText,
		ClientError:      translate(lang, "ClientError"),
		ServerError:      translate(lang, "ServerError"),
		WhatHappened:     translate(lang, "WhatHappened"),
		WhatCanIDo:       translate(lang, "WhatCanIDo"),
		Description:      getDescriptionTranslation(lang, status),
		WhatToDo:         getWhatToDoTranslation(lang, status),
		ClientCardState:  clientState,
		ClientCardText:   clientText,
		NetworkCardState: networkState,
		NetworkCardText:  networkText,
		ServerCardState:  serverState,
		ServerCardText:   serverText,
		Host:             translate(lang, "Host"),
		OriginalURI:      translate(lang, "OriginalURI"),
		TraceID:          translate(lang, "TraceID"),
		RequestID:        translate(lang, "RequestID"),
		EdgeID:           translate(lang, "EdgeID"),
		ContactSupport:   translate(lang, "ContactSupport"),
	}
}

// translate handles base dictionary translations
func translate(lang, key string) string {
	dict := map[string]map[string]string{
		"zh": {
			"ConnectionStatus": "连接状态",
			"YourClient":       "您的客户端",
			"Network":          "网络",
			"WebServer":        "Web 服务器",
			"Working":          "正常",
			"Unknown":          "未知",
			"ClientError":      "客户端错误",
			"ServerError":      "服务器错误",
			"WhatHappened":     "发生了什么？",
			"WhatCanIDo":       "我该怎么办？",
			"DefaultWhatToDo":  "请在几分钟后重试。",
			"Host":             "主机",
			"OriginalURI":      "原始 URI",
			"TraceID":          "追踪 ID",
			"RequestID":        "请求 ID",
			"EdgeID":           "边缘 ID",
			"ContactSupport":   "联系技术支持",
		},
		"en": {
			"ConnectionStatus": "Connection status",
			"YourClient":       "Your Client",
			"Network":          "Network",
			"WebServer":        "Web Server",
			"Working":          "Working",
			"Unknown":          "Unknown",
			"ClientError":      "Client Error",
			"ServerError":      "Server Error",
			"WhatHappened":     "What happened?",
			"WhatCanIDo":       "What can I do?",
			"DefaultWhatToDo":  "Please try again in a few minutes.",
			"Host":             "Host",
			"OriginalURI":      "Original URI",
			"TraceID":          "Trace ID",
			"RequestID":        "Request ID",
			"EdgeID":           "Edge ID",
			"ContactSupport":   "Contact Support",
		},
		"ar": {
			"ConnectionStatus": "حالة الاتصال",
			"YourClient":       "عميلك",
			"Network":          "الشبكة",
			"WebServer":        "خادم الويب",
			"Working":          "يعمل",
			"Unknown":          "غير معروف",
			"ClientError":      "خطأ في العميل",
			"ServerError":      "خطأ في الخادم",
			"WhatHappened":     "ماذا حدث؟",
			"WhatCanIDo":       "ماذا يمكنني أن أفعل؟",
			"DefaultWhatToDo":  "يرجى المحاولة مرة أخرى بعد بضع دقائق.",
			"Host":             "المضيف",
			"OriginalURI":      "عنوان URI الأصلي",
			"TraceID":          "معرف التتبع",
			"RequestID":        "معرف الطلب",
			"EdgeID":           "معرف الحافة",
			"ContactSupport":   "الاتصال بالدعم",
		},
		"fr": {
			"ConnectionStatus": "Statut de la connexion",
			"YourClient":       "Votre client",
			"Network":          "Réseau",
			"WebServer":        "Serveur Web",
			"Working":          "Opérationnel",
			"Unknown":          "Inconnu",
			"ClientError":      "Erreur du client",
			"ServerError":      "Erreur du serveur",
			"WhatHappened":     "Que s'est-il passé ?",
			"WhatCanIDo":       "Que puis-je faire ?",
			"DefaultWhatToDo":  "Veuillez réessayer dans quelques minutes.",
			"Host":             "Hôte",
			"OriginalURI":      "URI d'origine",
			"TraceID":          "ID de trace",
			"RequestID":        "ID de requête",
			"EdgeID":           "ID de bord",
			"ContactSupport":   "Contacter le support",
		},
		"ru": {
			"ConnectionStatus": "Статус подключения",
			"YourClient":       "Ваш клиент",
			"Network":          "Сеть",
			"WebServer":        "Веб-сервер",
			"Working":          "Работает",
			"Unknown":          "Неизвестно",
			"ClientError":      "Ошибка клиента",
			"ServerError":      "Ошибка сервера",
			"WhatHappened":     "Что произошло?",
			"WhatCanIDo":       "Что я могу сделать?",
			"DefaultWhatToDo":  "Пожалуйста, повторите попытку через несколько минут.",
			"Host":             "Хост",
			"OriginalURI":      "Исходный URI",
			"TraceID":          "Идентификатор трассировки",
			"RequestID":        "Идентификатор запроса",
			"EdgeID":           "Идентификатор границы",
			"ContactSupport":   "Связаться с поддержкой",
		},
		"es": {
			"ConnectionStatus": "Estado de la conexión",
			"YourClient":       "Su cliente",
			"Network":          "Red",
			"WebServer":        "Servidor web",
			"Working":          "Funcionando",
			"Unknown":          "Desconocido",
			"ClientError":      "Error del cliente",
			"ServerError":      "Error del servidor",
			"WhatHappened":     "¿Qué ha pasado?",
			"WhatCanIDo":       "¿Qué puedo hacer?",
			"DefaultWhatToDo":  "Por favor, inténtelo de nuevo en unos minutos.",
			"Host":             "Host",
			"OriginalURI":      "URI original",
			"TraceID":          "ID de traza",
			"RequestID":        "ID de solicitud",
			"EdgeID":           "ID de borde",
			"ContactSupport":   "Contactar con soporte",
		},
	}

	if langDict, ok := dict[lang]; ok {
		if val, ok := langDict[key]; ok {
			return val
		}
	}
	// Fallback to English
	if val, ok := dict["en"][key]; ok {
		return val
	}
	return key
}

func getWhatToDoTranslation(lang string, status int) string {
	if status >= 100 && status < 200 {
		switch lang {
		case "zh":
			return "请等待请求的进一步处理。"
		case "ar":
			return "يرجى الانتظار لمزيد من معالجة الطلب."
		case "fr":
			return "Veuillez patienter pour le traitement ultérieur de la requête."
		case "ru":
			return "Пожалуйста, подождите дальнейшей обработки запроса."
		case "es":
			return "Por favor, espere a que se procese la solicitud."
		default:
			return "Please wait for further processing of the request."
		}
	}
	if status >= 200 && status < 300 {
		switch lang {
		case "zh":
			return "请求已成功处理，无需额外操作。"
		case "ar":
			return "تم معالجة الطلب بنجاح، لا يلزم اتخاذ أي إجراء."
		case "fr":
			return "La requête a été traitée avec succès, aucune action requise."
		case "ru":
			return "Запрос успешно обработан, никаких действий не требуется."
		case "es":
			return "La solicitud se procesó correctamente, no se requiere ninguna acción."
		default:
			return "The request was successfully processed, no action needed."
		}
	}
	if status >= 300 && status < 400 {
		switch lang {
		case "zh":
			return "您已被重定向，请等待跳转或检查重定向设置。"
		case "ar":
			return "يتم إعادة توجيهك. يرجى الانتظار أو التحقق من إعدادات إعادة التوجيه."
		case "fr":
			return "Vous êtes redirigé. Veuillez patienter ou vérifier vos paramètres de redirection."
		case "ru":
			return "Вы перенаправляетесь. Пожалуйста, подождите или проверьте настройки перенаправления."
		case "es":
			return "Está siendo redirigido. Por favor, espere o compruebe su configuración de redirección."
		default:
			return "You are being redirected. Please wait or check your redirect settings."
		}
	}

	switch status {
	case 400, 405, 406, 411, 413:
		switch lang {
		case "zh":
			return "请检查请求方法、请求头、数据体或 URL。"
		case "ar":
			return "يرجى التحقق من طريقة الطلب أو الرؤوس أو الحمولة أو عنوان URL."
		case "fr":
			return "Veuillez vérifier la méthode de requête, les en-têtes, la charge utile ou l'URL."
		case "ru":
			return "Пожалуйста, проверьте метод запроса, заголовки, полезную нагрузку или URL."
		case "es":
			return "Por favor, compruebe el método de solicitud, los encabezados, la carga útil o la URL."
		default:
			return "Please check the request method, headers, payload, or URL."
		}
	case 401, 403, 407:
		switch lang {
		case "zh":
			return "请检查您的身份认证或访问权限。"
		case "ar":
			return "يرجى التحقق من ترخيصك أو أذونات الوصول الخاصة بك."
		case "fr":
			return "Veuillez vérifier votre autorisation ou vos permissions d'accès."
		case "ru":
			return "Пожалуйста, проверьте вашу авторизацию или разрешения на доступ."
		case "es":
			return "Por favor, compruebe su autorización o permisos de acceso."
		default:
			return "Please check your authorization or access permissions."
		}
	case 402:
		switch lang {
		case "zh":
			return "请检查您的支付状态或账户余额。"
		case "ar":
			return "يرجى التحقق من حالة الدفع أو رصيد الحساب."
		case "fr":
			return "Veuillez vérifier votre statut de paiement ou le solde de votre compte."
		case "ru":
			return "Пожалуйста, проверьте статус платежа или баланс счета."
		case "es":
			return "Por favor, compruebe su estado de pago o saldo de cuenta."
		default:
			return "Please check your payment status or account balance."
		}
	case 404:
		switch lang {
		case "zh":
			return "请仔细核对 URL 地址并重试。"
		case "ar":
			return "يرجى التحقق من عنوان URL والمحاولة مرة أخرى."
		case "fr":
			return "Veuillez double-vérifier l'URL et réessayer."
		case "ru":
			return "Пожалуйста, дважды проверьте URL и повторите попытку."
		case "es":
			return "Por favor, compruebe la URL e inténtelo de nuevo."
		default:
			return "Please double-check the URL and try again."
		}
	case 408, 420, 429:
		switch lang {
		case "zh":
			return "请稍等片刻，然后重试。"
		case "ar":
			return "يرجى الانتظار قليلاً ثم المحاولة مرة أخرى."
		case "fr":
			return "Veuillez patienter un court instant, puis réessayez."
		case "ru":
			return "Пожалуйста, подождите немного и повторите попытку."
		case "es":
			return "Por favor, espere un momento y vuelva a intentarlo."
		default:
			return "Please wait briefly, then try again."
		}
	case 409, 410, 418:
		switch lang {
		case "zh":
			return "请求已送达，但目标资源目前无法以预期形式访问。"
		case "ar":
			return "وصل الطلب إلينا، ولكن الهدف غير متاح بالشكل المتوقع."
		case "fr":
			return "La requête nous est parvenue, mais la cible n'est pas disponible sous la forme attendue."
		case "ru":
			return "Запрос дошел до нас, но цель недоступна в ожидаемом виде."
		case "es":
			return "La solicitud nos ha llegado, pero el objetivo no está disponible en la forma esperada."
		default:
			return "The request reached us, but the target is not available in its expected form."
		}
	case 412, 428:
		switch lang {
		case "zh":
			return "请检查请求的先决条件或请求头。"
		case "ar":
			return "يرجى التحقق من الشروط المسبقة للطلب أو الرؤوس."
		case "fr":
			return "Veuillez vérifier les préconditions ou les en-têtes de la requête."
		case "ru":
			return "Пожалуйста, проверьте предварительные условия или заголовки запроса."
		case "es":
			return "Por favor, compruebe las condiciones previas o los encabezados de la solicitud."
		default:
			return "Please check the request preconditions or headers."
		}
	case 414, 431:
		switch lang {
		case "zh":
			return "请缩短 URL 或减小请求头的大小。"
		case "ar":
			return "يرجى تقصير عنوان URL أو تقليل حجم رؤوس الطلب."
		case "fr":
			return "Veuillez raccourcir l'URL ou réduire la taille des en-têtes de requête."
		case "ru":
			return "Пожалуйста, сократите URL или уменьшите размер заголовков запроса."
		case "es":
			return "Por favor, acorte la URL o reduzca el tamaño de los encabezados de la solicitud."
		default:
			return "Please shorten the URL or reduce the size of the request headers."
		}
	case 415:
		switch lang {
		case "zh":
			return "请使用支持的媒体格式或 Content-Type。"
		case "ar":
			return "يرجى استخدام تنسيق وسائط مدعوم أو Content-Type."
		case "fr":
			return "Veuillez utiliser un format multimédia ou un Content-Type pris en charge."
		case "ru":
			return "Пожалуйста, используйте поддерживаемый формат мультимедиа или Content-Type."
		case "es":
			return "Por favor, utilice un formato de medio o Content-Type compatible."
		default:
			return "Please use a supported media format or Content-Type."
		}
	case 416:
		switch lang {
		case "zh":
			return "请调整请求的范围字段并重试。"
		case "ar":
			return "يرجى ضبط نطاق الطلب والمحاولة مرة أخرى."
		case "fr":
			return "Veuillez ajuster la plage demandée et réessayer."
		case "ru":
			return "Пожалуйста, скорректируйте запрашиваемый диапазон и повторите попытку."
		case "es":
			return "Por favor, ajuste el rango solicitado e inténtelo de nuevo."
		default:
			return "Please adjust the requested range and try again."
		}
	case 417:
		switch lang {
		case "zh":
			return "请检查 Expect 请求头并重试。"
		case "ar":
			return "يرجى التحقق من رأس Expect والمحاولة مرة أخرى."
		case "fr":
			return "Veuillez vérifier l'en-tête Expect et réessayer."
		case "ru":
			return "Пожалуйста, проверьте заголовок Expect и повторите попытку."
		case "es":
			return "Por favor, compruebe el encabezado Expect e inténtelo de nuevo."
		default:
			return "Please check the Expect headers and try again."
		}
	case 422, 423, 424:
		switch lang {
		case "zh":
			return "请检查提交的数据格式或相关依赖项状态。"
		case "ar":
			return "يرجى التحقق من تنسيق البيانات المقدمة أو حالة التبعيات ذات الصلة."
		case "fr":
			return "Veuillez vérifier le format des données soumises ou l'état des dépendances associées."
		case "ru":
			return "Пожалуйста, проверьте формат отправленных данных или статус зависимостей."
		case "es":
			return "Por favor, compruebe el formato de los datos enviados o el estado de las dependencias relacionadas."
		default:
			return "Please check the submitted data format or dependency states."
		}
	case 425:
		switch lang {
		case "zh":
			return "请稍后重试该请求。"
		case "ar":
			return "يرجى الانتظار وإعادة محاولة الطلب."
		case "fr":
			return "Veuillez patienter et réessayer la requête."
		case "ru":
			return "Пожалуйста, подождите и повторите запрос."
		case "es":
			return "Por favor, espere y vuelva a intentar la solicitud."
		default:
			return "Please wait and retry the request."
		}
	case 426:
		switch lang {
		case "zh":
			return "请升级您的浏览器或客户端协议版本。"
		case "ar":
			return "يرجى ترقية متصفحك أو إصدار بروتوكول العميل."
		case "fr":
			return "Veuillez mettre à niveau votre navigateur ou la version du protocole client."
		case "ru":
			return "Пожалуйста, обновите ваш браузер или версию протокола клиента."
		case "es":
			return "Por favor, actualice su navegador o versión del protocolo de cliente."
		default:
			return "Please upgrade your browser or client protocol version."
		}
	case 444, 499:
		switch lang {
		case "zh":
			return "连接已非正常断开，请检查网络连接。"
		case "ar":
			return "تم قطع الاتصال بشكل غير طبيعي، يرجى التحقق من اتصال الشبكة."
		case "fr":
			return "La connexion a été interrompue anormalement, veuillez vérifier la connexion réseau."
		case "ru":
			return "Соединение было ненормально разорвано, пожалуйста, проверьте сетевое подключение."
		case "es":
			return "La conexión se ha interrumpido de forma anormal, compruebe la conexión de red."
		default:
			return "The connection was abnormally closed, please check your network connection."
		}
	case 449:
		switch lang {
		case "zh":
			return "请提供所需的信息并重试。"
		case "ar":
			return "يرجى تقديم المعلومات المطلوبة والمحاولة مرة أخرى."
		case "fr":
			return "Veuillez fournir les informations requises et réessayer."
		case "ru":
			return "Пожалуйста, предоставьте необходимую информацию и повторите попытку."
		case "es":
			return "Por favor, proporcione la información requerida e inténtelo de nuevo."
		default:
			return "Please provide the required information and retry."
		}
	case 450, 451:
		switch lang {
		case "zh":
			return "该资源在您的地区受限，无法直接访问。"
		case "ar":
			return "هذا المورد مقيد في منطقتك ولا يمكن الوصول إليه مباشرة."
		case "fr":
			return "Cette ressource est restreinte dans votre région et n'est pas accessible directement."
		case "ru":
			return "Этот ресурс ограничен в вашем регионе и недоступен напрямую."
		case "es":
			return "Este recurso está restringido en su región y no se puede acceder directamente."
		default:
			return "This resource is restricted in your region and cannot be accessed directly."
		}
	case 502:
		switch lang {
		case "zh":
			return "网关收到无效响应，请稍后重试。"
		case "ar":
			return "تلقى البوابة استجابة غير صالحة. يرجى إعادة المحاولة قريبًا."
		case "fr":
			return "La passerelle a reçu une réponse invalide. Veuillez réessayer sous peu."
		case "ru":
			return "Шлюз получил недействительный ответ. Пожалуйста, повторите попытку в ближайшее время."
		case "es":
			return "La puerta de enlace recibió una respuesta no válida. Por favor, inténtelo de nuevo en breve."
		default:
			return "The gateway received an invalid response. Please retry shortly."
		}
	case 503:
		switch lang {
		case "zh":
			return "服务暂时不可用，请稍后重试。"
		case "ar":
			return "الخدمة غير متوفرة مؤقتًا. يرجى المحاولة مرة أخرى لاحقًا."
		case "fr":
			return "Le service est temporairement indisponible. Veuillez réessayer plus tard."
		case "ru":
			return "Служба временно недоступна. Пожалуйста, повторите попытку позже."
		case "es":
			return "El servicio no está disponible temporalmente. Por favor, inténtelo de nuevo más tarde."
		default:
			return "The service is temporarily unavailable. Please try again later."
		}
	case 504, 598, 599:
		switch lang {
		case "zh":
			return "服务器响应超时，请检查网络或稍后重试。"
		case "ar":
			return "انتهت مهلة استجابة الخادم. يرجى التحقق من الشبكة أو إعادة المحاولة لاحقًا."
		case "fr":
			return "Le serveur a mis trop de temps à répondre. Veuillez vérifier le réseau ou réessayer."
		case "ru":
			return "Время ожидания сервера истекло. Пожалуйста, проверьте сеть или повторите попытку позже."
		case "es":
			return "Se agotó el tiempo de espera del servidor. Compruebe la red o inténtelo de nuevo más tarde."
		default:
			return "The server took too long to respond. Please check your network or retry shortly."
		}
	default:
		if status >= 500 && status < 600 {
			switch lang {
			case "zh":
				return "服务器内部错误，程序员哥哥正在抢修，请稍后重试。"
			case "ar":
				return "خطأ داخلي في الخادم. يرجى المحاولة مرة أخرى لاحقًا."
			case "fr":
				return "Erreur interne du serveur. Veuillez réessayer plus tard."
			case "ru":
				return "Внутренняя ошибка сервера. Пожалуйста, повторите попытку позже."
			case "es":
				return "Error interno del servidor. Por favor, inténtelo de nuevo más tarde."
			default:
				return "Internal server error. Please try again in a few minutes."
			}
		}
		return translate(lang, "DefaultWhatToDo")
	}
}

func getDescriptionTranslation(lang string, status int) string {
	if status >= 100 && status < 200 {
		switch lang {
		case "zh":
			return "这是一个临时的中间响应，请不用担心，一切都在顺利处理中呢~"
		case "ar":
			return "هذه استجابة مؤقتة، لا تقلق، كل شيء يتم معالجته بسلاسة~"
		case "fr":
			return "Ceci est une réponse intermédiaire temporaire, ne t'inquiète pas, tout se déroule bien~"
		case "ru":
			return "Это временный промежуточный ответ, не беспокойтесь, все обрабатывается успешно~"
		case "es":
			return "Esta es una respuesta intermedia temporal, no te preocupes, todo se está procesando bien~"
		default:
			return "This is a temporary informational response, everything is processing smoothly~"
		}
	}
	if status >= 200 && status < 300 {
		switch lang {
		case "zh":
			return "太棒啦！请求已经成功完成，资源状态棒棒哒~ ✨"
		case "ar":
			return "رائع! تم إكمال الطلب بنجاح، حالة المورد ممتازة~ ✨"
		case "fr":
			return "Super ! La requête s'est déroulée avec succès, tout est parfait~ ✨"
		case "ru":
			return "Отлично! Запрос успешно выполнен, статус ресурса в полном порядке~ ✨"
		case "es":
			return "¡Genial! La solicitud se ha completado correctamente, el estado es estupendo~ ✨"
		default:
			return "Awesome! The request completed successfully and everything is fine~ ✨"
		}
	}
	if status >= 300 && status < 400 {
		switch lang {
		case "zh":
			return "地址发生了变动，浏览器正在乖乖地帮你跳转到新的目的地哦~ ✈️"
		case "ar":
			return "لقد تغير العنوان، المتصفح يقوم بتوجيهك إلى الوجهة الجديدة~ ✈️"
		case "fr":
			return "L'adresse a changé, le navigateur est en train de te rediriger vers la nouvelle destination~ ✈️"
		case "ru":
			return "Адрес изменился, браузер послушно перенаправляет вас в новое место назначения~ ✈️"
		case "es":
			return "La dirección ha cambiado, el navegador te está redirigiendo al nuevo destino~ ✈️"
		default:
			return "The address has changed, the browser is redirecting you to the new destination~ ✈️"
		}
	}

	switch status {
	case 400:
		switch lang {
		case "zh":
			return "呜呜，请求好像有点小脾气，服务器看不懂啦。请检查一下参数、格式或者 URL 再试一次嘛~(>_<)"
		case "ar":
			return "أوه، يبدو أن الطلب به بعض المشاكل الطفيفة ولم يتمكن الخادم من فهمه. يرجى التحقق من المعلمات أو التنسيق والمحاولة مرة أخرى~(>_<)"
		case "fr":
			return "Oh non, la requête semble faire un petit caprice, le serveur n'y comprend rien. S'il te plaît, vérifie les paramètres, le format ou l'URL et réessaie~(>_<)"
		case "ru":
			return "Ой-ой, у запроса, похоже, скверный характер, и сервер его не понимает. Пожалуйста, проверьте параметры, формат или URL и попробуйте еще раз~(>_<)"
		case "es":
			return "¡Uups! Parece que la solicitud tiene un pequeño berrinche y el servidor no la entiende. Por favor, comprueba los parámetros, el formato o la URL e inténtalo de nuevo~(>_<)"
		default:
			return "Aww, the request seems to have a tiny temper, and the server can't understand it. Please check the parameters, format, or URL and try again~(>_<)"
		}
	case 401:
		switch lang {
		case "zh":
			return "站住！这里是神秘区域哦，需要输入正确的身份凭证（钥匙）才能通过呢~ 🔑"
		case "ar":
			return "قف! هذه منطقة غامضة، ستحتاج إلى مفتاح الهوية الصحيح للمرور~ 🔑"
		case "fr":
			return "Halte-là ! C'est une zone mystérieuse ici, tu as besoin de la bonne clé d'authentification pour passer~ 🔑"
		case "ru":
			return "Стой! Это таинственная зона, для входа понадобятся правильные ключи (учетные данные)~ 🔑"
		case "es":
			return "¡Alto ahí! Esta es una zona misteriosa, necesitarás la llave (credenciales) correcta para pasar~ 🔑"
		default:
			return "Halt! This is a mysterious zone, you'll need the correct key (credentials) to enter~ 🔑"
		}
	case 402:
		switch lang {
		case "zh":
			return "哎呀，这个资源是付费的哦，需要先完成支付才能继续访问呢~ 💰"
		case "ar":
			return "أوه، هذا المورد يتطلب الدفع. يرجى إتمام الدفع للوصول إليه~ 💰"
		case "fr":
			return "Oups, cette ressource nécessite un paiement. S'il te plaît, effectue le paiement pour y accéder~ 💰"
		case "ru":
			return "Ой, этот ресурс платный. Пожалуйста, завершите оплату для доступа к нему~ 💰"
		case "es":
			return "¡Oops! Este recurso requiere pago. Por favor, realiza el pago para acceder~ 💰"
		default:
			return "Oops, this resource requires payment. Please complete the payment to access it~ 💰"
		}
	case 403:
		switch lang {
		case "zh":
			return "唔…虽然你亮明了身份，但本大人还是不能让你过去。这里是禁止通行的禁区哦！"
		case "ar":
			return "همم... على الرغم من إثبات هويتك، لا يمكنني السماح لك بالمرور. هذه منطقة محظورة تمامًا!"
		case "fr":
			return "Hmm... même si tu as montré patte blanche, je ne peux pas te laisser passer. C'est une zone strictement interdite !"
		case "ru":
			return "Хм... хотя ты и показал свои документы, я все равно не могу тебя пропустить. Вход сюда строго воспрещен!"
		case "es":
			return "Mmm... aunque te hayas identificado, no puedo dejarte pasar. ¡Esta es una zona estrictamente restringida!"
		default:
			return "Hmm... even though you've shown your identity, I still can't let you pass. This is a strictly restricted area!"
		}
	case 404:
		switch lang {
		case "zh":
			return "诶？你找的页面好像和本喵走丢了，在宇宙深处迷路了喵~ 🐾"
		case "ar":
			return "هاه؟ يبدو أن الصفحة التي تبحث عنها قد تاهت معي وضاعت في أعماق الفضاء~ 🐾"
		case "fr":
			return "Hein ? La page que tu cherches semble s'être égarée et s'est perdue dans l'espace intersidéral~ 🐾"
		case "ru":
			return "Ой? Страничка, которую ты ищешь, куда-то убежала и потерялась в глубинах космоса~ 🐾"
		case "es":
			return "¿Eh? Parece que la página que buscas se ha escapado y se ha perdido en el espacio profundo~ 🐾"
		default:
			return "Huh? The page you're looking for seems to have wandered off and got lost in the deep space~ 🐾"
		}
	case 405:
		switch lang {
		case "zh":
			return "这个请求姿势（Method）不对啦！服务器说它不能接受这种敲门方式哦~"
		case "ar":
			return "طريقة الطلب هذه غير صحيحة! يقول الخادم إنه لا يمكنه قبول طريقة طرق الباب هذه~"
		case "fr":
			return "Cette posture de requête (Method) n'est pas la bonne ! Le serveur dit qu'il ne peut pas accepter cette façon de frapper à la porte~"
		case "ru":
			return "Этот жест запроса (Method) неверен! Сервер говорит, что не может принять такой стук в дверь~"
		case "es":
			return "¡Esa postura de solicitud (Method) no es correcta! El servidor dice que no acepta esta forma de llamar a la puerta~"
		default:
			return "That request posture (Method) isn't right! The server says it can't accept this way of knocking on the door~"
		}
	case 407:
		switch lang {
		case "zh":
			return "代理服务器拦住你啦！需要先通过代理身份验证哦~"
		case "ar":
			return "خادم الوكيل أوقفك! يجب عليك اجتياز مصادقة الوكيل أولاً~"
		case "fr":
			return "Le serveur proxy t'a arrêté ! Tu dois d'abord passer l'authentification du proxy~"
		case "ru":
			return "Прокси-сервер остановил тебя! Сначала нужно пройти аутентификацию на прокси~"
		case "es":
			return "¡El servidor proxy te ha detenido! Debes pasar la autenticación del proxy primero~"
		default:
			return "The proxy server stopped you! You need to pass proxy authentication first~"
		}
	case 408:
		switch lang {
		case "zh":
			return "等得花儿都谢了……请求超时啦，网速可能在开小差，重新发送一下试试？"
		case "ar":
			return "انتظرنا طويلاً حتى ذبلت الزهور... انتهت مهلة الطلب! ربما تكون سرعة الإنترنت بطيئة، حاول إعادة الإرسال؟"
		case "fr":
			return "J'ai attendu si longtemps que les fleurs ont fané... Requête expirée ! Peut-être que le réseau fait la sieste ? Réessaie d'envoyer ?"
		case "ru":
			return "Ждали так долго, что цветы завяли... Время запроса истекло! Может, сеть уснула? Попробуй отправить еще раз?"
		case "es":
			return "He esperado tanto que las flores se han marchitado... ¡Tiempo de espera agotado! ¿Quizás la red se ha quedado dormida? ¿Probamos a enviar de nuevo?"
		default:
			return "Waited so long that the flowers withered... Request timeout! Maybe the connection is slacking off? Try sending again?"
		}
	case 409:
		switch lang {
		case "zh":
			return "哎呀，服务器内部发生了点小摩擦（冲突），大家在抢同一个资源呢，稍等下再来试试呗？"
		case "ar":
			return "أوه، حدث بعض الاحتكاك الطفيف (التعارض) داخل الخادم! الجميع يتنافسون على نفس المورد، حاول مرة أخرى بعد قليل؟"
		case "fr":
			return "Oups, une petite friction (conflit) s'est produite en interne ! Tout le monde s'arrache la même ressource, réessaie dans un instant ?"
		case "ru":
			return "Ой, внутри произошло небольшое трение (конфликт)! Все пытаются схватить один и тот же ресурс, попробуй еще раз чуть позже?"
		case "es":
			return "¡Oops! Ha ocurrido un pequeño conflicto interno. Todos están intentando acceder al mismo recurso, ¿probamos de nuevo en un momento?"
		default:
			return "Oops, a tiny friction (conflict) happened inside! Everyone is grabbing the same resource, try again in a bit?"
		}
	case 410:
		switch lang {
		case "zh":
			return "那个宝贵的资源已经彻底搬家啦，而且没有留下新地址，追不回来啦QAQ"
		case "ar":
			return "لقد انتقل هذا المورد الثمين تمامًا ولم يترك عنوانًا جديدًا. لا يمكن استعادته QAQ"
		case "fr":
			return "Cette précieuse ressource a déménagé définitivement sans laisser de nouvelle adresse. Impossible de la retrouver QAQ"
		case "ru":
			return "Этот ценный ресурс переехал навсегда и не оставил нового адреса. Его больше не вернуть QAQ"
		case "es":
			return "Ese valioso recurso se ha mudado definitivamente y no ha dejado dirección nueva. Se ha ido para siempre QAQ"
		default:
			return "That precious resource has completely moved away and left no new address. It's gone forever QAQ"
		}
	case 411:
		switch lang {
		case "zh":
			return "服务器需要知道你发的数据有多长，请在请求里加上长度信息（Content-Length）哦~"
		case "ar":
			return "يحتاج الخادم إلى معرفة حجم البيانات المرسلة. يرجى إضافة رأس Content-Length~"
		case "fr":
			return "Le serveur doit savoir quelle est la taille de tes données. S'il te plaît, ajoute un en-tête Content-Length~"
		case "ru":
			return "Серверу нужно знать длину твоих данных. Пожалуйста, добавь заголовок Content-Length~"
		case "es":
			return "El servidor necesita saber el tamaño de tus datos. Por favor, añade un encabezado Content-Length~"
		default:
			return "The server needs to know how long your data is. Please add a Content-Length header~"
		}
	case 412, 428:
		switch lang {
		case "zh":
			return "请求的先决条件不满足，或者缺少必要的头部条件哦~"
		case "ar":
			return "لم يتم استيفاء الشروط المسبقة للطلب، أو هناك نقص في الرؤوس المطلوبة~"
		case "fr":
			return "Les préconditions de la requête ne sont pas remplies, ou des en-têtes requis manquent~"
		case "ru":
			return "Предварительные условия запроса не соблюдены или отсутствуют обязательные заголовки~"
		case "es":
			return "No se cumplen las condiciones previas de la solicitud o faltan encabezados obligatorios~"
		default:
			return "The request preconditions were not met, or required headers are missing~"
		}
	case 413:
		switch lang {
		case "zh":
			return "哇！你给的数据包太胖啦，服务器抱不动了！快去给它瘦个身吧~"
		case "ar":
			return "واو! حزمة البيانات التي أرسلتها كبيرة جدًا، الخادم لا يمكنه حملها! اذهب وقم بتقليل حجمها~"
		case "fr":
			return "Wow ! Le paquet de données est trop lourd, le serveur ne peut pas le porter ! Va lui faire faire un petit régime~"
		case "ru":
			return "Ого! Пакет данных слишком тяжелый, сервер не может его поднять! Иди сделай его немного стройнее~"
		case "es":
			return "¡Guau! El paquete de datos es demasiado pesado, ¡el servidor no puede con él! Ve a recortarlo un poco~"
		default:
			return "Wow! The data payload is too heavy, the server can't carry it! Go make it slim down~"
		}
	case 414, 431:
		switch lang {
		case "zh":
			return "数据内容太长太庞大啦，超出了服务器的处理能力极限哦~"
		case "ar":
			return "محتوى البيانات طويل جدًا وضخم للغاية، ويتجاوز حدود معالجة الخادم~"
		case "fr":
			return "Le contenu des données est trop long ou trop volumineux, dépassant la capacité de traitement du serveur~"
		case "ru":
			return "Содержимое данных слишком длинное или объемное, что превышает возможности обработки сервера~"
		case "es":
			return "El contenido de los datos es demasiado largo o voluminoso, superando la capacidad de procesamiento del servidor~"
		default:
			return "The request URI or header fields are too large for the server to process~"
		}
	case 415:
		switch lang {
		case "zh":
			return "你递过来的数据格式，服务器表示看不懂、没办法支持解析呀~"
		case "ar":
			return "تنسيق البيانات الذي قدمته غير مدعوم ولا يمكن للخادم تحليله~"
		case "fr":
			return "Le format des données soumises n'est pas pris en charge ou analysé par le serveur~"
		case "ru":
			return "Формат переданных данных не поддерживается и не может быть обработан сервером~"
		case "es":
			return "El servidor no admite ni puede analizar el formato de los datos enviados~"
		default:
			return "The server does not support the media format of the requested data~"
		}
	case 416:
		switch lang {
		case "zh":
			return "请求的资源范围超出合理范围，服务器拿不出你要的部分数据呢~"
		case "ar":
			return "يتجاوز نطاق المورد المطلوب النطاق المعقول، ولا يمكن للخادم توفيره~"
		case "fr":
			return "La plage demandée dépasse les limites raisonnables, le serveur ne peut pas la fournir~"
		case "ru":
			return "Запрошенный диапазон ресурса выходит за допустимые пределы, сервер не может его предоставить~"
		case "es":
			return "El rango solicitado supera los límites razonables, el servidor no puede proporcionarlo~"
		default:
			return "The requested range of the resource cannot be satisfied by the server~"
		}
	case 417:
		switch lang {
		case "zh":
			return "服务器没办法达成你的预期期望，请求有点落空了QAQ"
		case "ar":
			return "لم يتمكن الخادم من تلبية توقعاتك، الطلب باء بالفشل QAQ"
		case "fr":
			return "Le serveur n'a pas pu répondre aux attentes spécifiées, la requête a échoué QAQ"
		case "ru":
			return "Сервер не смог удовлетворить указанные ожидания, запрос не удался QAQ"
		case "es":
			return "El servidor no ha podido cumplir con las expectativas especificadas, la solicitud falló QAQ"
		default:
			return "The server could not meet the expectations specified in the Expect headers~"
		}
	case 418:
		switch lang {
		case "zh":
			return "人家其实是一只茶壶啦，泡茶我在行，处理请求真的超纲了咩~ 🍵"
		case "ar":
			return "أنا في الواقع مجرد إبريق شاي، تخمير الشاي هو تخصصي، لكن معالجة الطلبات تفوق قدرتي تمامًا~ 🍵"
		case "fr":
			return "Je ne suis qu'une théière en fait, faire du thé c'est ma spécialité, mais traiter des requêtes dépasse largement mes compétences~ 🍵"
		case "ru":
			return "На самом деле я просто чайник, заваривать чай — мое призвание, но обрабатывать запросы — это совсем не мое~ 🍵"
		case "es":
			return "En realidad soy solo una tetera. Lo mío es hacer té, pero procesar solicitudes está fuera de mi alcance~ 🍵"
		default:
			return "I'm actually just a teapot, brewing tea is my thing, but processing requests is way out of my league~ 🍵"
		}
	case 420, 429:
		switch lang {
		case "zh":
			return "手速太快啦！服务器要被你戳晕了，先喝杯茶休息一下再来敲门吧~ ☕"
		case "ar":
			return "سرعتك عالية جدًا! الخادم يشعر بالدوار من كثرة النقرات. اشرب كوبًا من الشاي واسترح قبل طرق الباب مجددًا~ ☕"
		case "fr":
			return "Trop rapide ! Le serveur a le tournis à force de se faire tapoter. Prends une tasse de thé et repose-toi avant de refrapper~ ☕"
		case "ru":
			return "Слишком быстро! Сервер уже кружится от твоих кликов. Выпей чашечку чая и отдохни, прежде чем постучать снова~ ☕"
		case "es":
			return "¡Demasiado rápido! El servidor se está mareando de tantos clics. Tómate una taza de té y descansa antes de volver a llamar~ ☕"
		default:
			return "Too fast! The server is getting dizzy from all the pokes. Have a cup of tea and rest before knocking again~ ☕"
		}
	case 422, 423, 424:
		switch lang {
		case "zh":
			return "请求很完整，但包含的内容有语义错误，或者被锁住了，没办法执行成功~"
		case "ar":
			return "الطلب مكتمل، ولكنه يحتوي على أخطاء دلالية أو أنه مقفل ولا يمكن تنفيذه~"
		case "fr":
			return "La requête est complète, mais contient des erreurs sémantiques ou est verrouillée et ne peut pas être exécutée~"
		case "ru":
			return "Запрос синтаксически корректен, но содержит семантические ошибки или заблокирован~"
		case "es":
			return "La solicitud está completa, pero contiene errores semánticos o está bloqueada y no se puede ejecutar~"
		default:
			return "The request was well-formed but cannot be processed due to semantic errors or lock constraints~"
		}
	case 425:
		switch lang {
		case "zh":
			return "服务器不愿意承担重放攻击的风险，请稍微晚一点点再试吧~"
		case "ar":
			return "الخادم لا يريد تحمل مخاطر هجمات إعادة التشغيل، يرجى المحاولة لاحقًا~"
		case "fr":
			return "Le serveur ne souhaite pas prendre le risque d'une attaque par rejeu, réessaie plus tard~"
		case "ru":
			return "Сервер не хочет рисковать из-за возможных атак повторного воспроизведения, попробуйте позже~"
		case "es":
			return "El servidor no quiere arriesgarse a un ataque de reproducción, inténtalo de nuevo más tarde~"
		default:
			return "The server is unwilling to risk processing a request that might be replayed~"
		}
	case 426:
		switch lang {
		case "zh":
			return "服务器要求更高级的安全传输协议，请升级你们的沟通频道吧~"
		case "ar":
			return "يتطلب الخادم بروتوكول نقل أكثر أمانًا، يرجى الترقية~"
		case "fr":
			return "Le serveur exige un protocole de transmission plus sécurisé, veuillez le mettre à niveau~"
		case "ru":
			return "Сервер требует более безопасный протокол передачи, пожалуйста, обновите его~"
		case "es":
			return "El servidor requiere un protocolo de transmisión más seguro, por favor actualice~"
		default:
			return "The server requires a newer protocol to fulfill the request~"
		}
	case 444, 499:
		switch lang {
		case "zh":
			return "连接被关闭了，可能是在响应完成前，某方主动挂断了电话QAQ"
		case "ar":
			return "تم إغلاق الاتصال، ربما قام أحد الطرفين بإنهاء الاتصال قبل اكتماله QAQ"
		case "fr":
			return "La connexion a été fermée, probablement parce qu'une partie a raccroché avant la fin QAQ"
		case "ru":
			return "Соединение закрыто, возможно, одна из сторон повесила трубку до завершения ответа QAQ"
		case "es":
			return "La conexión se cerró, probablemente porque alguna parte colgó antes de completarse QAQ"
		default:
			return "The connection was closed before the request could be completed QAQ"
		}
	case 449:
		switch lang {
		case "zh":
			return "信息不够完善，请按照要求补充内容后再派发请求吧~"
		case "ar":
			return "المعلومات غير كافية، يرجى إكمالها وإعادة المحاولة~"
		case "fr":
			return "Informations insuffisantes, veuillez compléter selon les exigences et réessayer~"
		case "ru":
			return "Информация неполна, пожалуйста, заполните ее в соответствии с требованиями и повторите попытку~"
		case "es":
			return "La información no es suficiente, complétela de acuerdo con los requisitos y vuelva a intentarlo~"
		default:
			return "The request should be retried with the required information~"
		}
	case 450, 451:
		switch lang {
		case "zh":
			return "受家长控制或法律法规限制，该内容对您处于不可达状态哦。"
		case "ar":
			return "هذا المحتوى غير متاح لك بسبب قيود الرقابة الأبوية أو القوانين."
		case "fr":
			return "Ce contenu n'est pas accessible en raison de restrictions parentales ou de lois."
		case "ru":
			return "Этот контент недоступен для вас из-за родительского контроля или законов."
		case "es":
			return "Este contenido no está disponible para usted debido a restricciones parentales o leyes."
		default:
			return "This content is blocked by parental controls or unavailable due to legal reasons."
		}
	case 500:
		switch lang {
		case "zh":
			return "抱歉哦，服务器的小马达突然卡住了，程序员哥哥正在疯狂抢修中！"
		case "ar":
			return "عذرًا، لقد توقف محرك الخادم الصغير فجأة. المبرمجون يعملون بجنون لإصلاحه!"
		case "fr":
			return "Désolé, le petit moteur du serveur s'est brusquement bloqué. Nos développeurs s'activent frénétiquement pour réparer ça !"
		case "ru":
			return "Извини, маленький моторчик сервера внезапно заклинило. Наши разработчики уже вовсю его чинят!"
		case "es":
			return "Lo sentimos, el pequeño motor del servidor se ha atascado de repente. ¡Nuestros desarrolladores están trabajando frenéticamente para solucionarlo!"
		default:
			return "Sorry, the server's little motor suddenly got stuck. Our developers are frantically fixing it!"
		}
	case 501:
		switch lang {
		case "zh":
			return "这个功能服务器还没学会呢，等程序员哥哥把它开发出来吧~"
		case "ar":
			return "الخادم لم يتعلم هذه الميزة بعد. انتظر حتى يقوم المطورون ببنائها~"
		case "fr":
			return "Le serveur n'a pas encore appris cette fonctionnalité. Patiente le temps que nos développeurs la construisent~"
		case "ru":
			return "Сервер еще не научился этой функции. Подожди, пока наши разработчики ее создадут~"
		case "es":
			return "El servidor aún no ha aprendido esta función. Espera a que nuestros desarrolladores la programen~"
		default:
			return "The server hasn't learned this feature yet. Wait for our developers to build it~"
		}
	case 502:
		switch lang {
		case "zh":
			return "哎呀，网关在帮别的服务器传话时，对方突然断线了，真是个糟糕的传话筒！"
		case "ar":
			return "أوه، بينما كانت البوابة تنقل الرسائل لخادم آخر، انقطع اتصال الطرف الآخر فجأة. يا له من مرسل سيء!"
		case "fr":
			return "Oups, pendant que la passerelle relayait les messages pour un autre serveur, l'autre côté s'est déconnecté. Quel mauvais messager !"
		case "ru":
			return "Ой, пока шлюз передавал сообщения для другого сервера, тот внезапно отключился. Какой плохой почтальон!"
		case "es":
			return "Oops, mientras la puerta de enlace transmitía mensajes para otro servidor, la otra parte se desconectó. ¡Qué mal mensajero!"
		default:
			return "Oops, while the gateway was relaying messages for another server, the other side went offline. What a bad messenger!"
		}
	case 503:
		switch lang {
		case "zh":
			return "服务器今天太累了，正在闭关修炼（维护中）或者被大家挤爆了，稍后再来找我玩吧~"
		case "ar":
			return "الخادم متعب جدًا اليوم. إنه في فترة صيانة أو مزدحم للغاية. تعال للعب معي لاحقًا~"
		case "fr":
			return "Le serveur est trop fatigué aujourd'hui. Il est en pleine méditation (maintenance) ou surchargé. Reviens jouer avec moi plus tard~"
		case "ru":
			return "Сервер сегодня слишком устал. Он ушел в себя (на обслуживание) или перегружен. Заходи поиграть позже~"
		case "es":
			return "El servidor está demasiado cansado hoy. Está en mantenimiento o sobrecargado. ¡Vuelve a jugar conmigo más tarde~"
		default:
			return "The server is too tired today. It's practicing in isolation (maintenance) or overloaded. Come play with me later~"
		}
	case 504, 598, 599:
		switch lang {
		case "zh":
			return "呜，上游服务器迟迟没有回音，网关等到花儿都谢了也只能放弃啦。"
		case "ar":
			return "آه، استغرق الخادم الرئيسي وقتًا طويلاً للرد. انتظرت البوابة حتى ذبلت الزهور وكان عليها الاستسلام."
		case "fr":
			return "Euh, le serveur amont a mis trop de temps à répondre. La passerelle a attendu que les fleurs fanent et a dû abandonner."
		case "ru":
			return "Увы, вышестоящий сервер слишком долго не отвечал. Шлюз ждал до последнего, но пришлось сдаться."
		case "es":
			return "Uff, el servidor ascendente tardó demasiado en responder. La puerta de enlace esperó hasta que se marchitaron las flores y tuvo que rendirse."
		default:
			return "Ugh, the upstream server took too long to reply. The gateway waited until the flowers withered and had to give up."
		}
	default:
		if status >= 400 && status < 500 {
			switch lang {
			case "zh":
				return "客户端好像出了点状况，请求没办法顺利完成，检查下小细节吧~"
			case "ar":
				return "حدث خطأ ما من جانب العميل. لا يمكن إكمال الطلب، يرجى التحقق من التفاصيل~"
			case "fr":
				return "Quelque chose s'est mal passé côté client. La requête n'a pas pu aboutir, vérifie les détails~"
			case "ru":
				return "Что-то пошло не так со стороны клиента. Запрос не удалось завершить, проверь детали~"
			case "es":
				return "Algo salió mal por parte del cliente. La solicitud no se pudo completar, comprueba los detalles~"
			default:
				return "Something went wrong on the client side. The request couldn't be completed, check the details~"
			}
		}
		if status >= 500 && status < 600 {
			switch lang {
			case "zh":
				return "服务器内部好像有点头晕，暂时没办法处理你的请求，请稍候再试喵~"
			case "ar":
				return "يشعر الخادم ببعض الدوار ولا يمكنه معالجة طلبك حاليًا. حاول مرة أخرى لاحقًا~"
			case "fr":
				return "Le serveur a un petit coup de barre en interne et ne peut pas traiter ta requête pour le moment. Réessaie tard~"
			case "ru":
				return "Серверу внутри немного нехорошо, он не может сейчас обработать твой запрос. Попробуй позже~"
			case "es":
				return "El servidor se siente un poco mareado internamente y no puede procesar tu solicitud por ahora. Inténtalo más tarde~"
			default:
				return "The server feels a bit dizzy inside and can't process your request for now. Try again later~"
			}
		}
		switch lang {
		case "zh":
			return "遭遇了未知的神秘状况呢，请稍后再试一次吧~"
		case "ar":
			return "واجهنا موقفًا غامضًا غير معروف. يرجى المحاولة مرة أخرى لاحقًا~"
		case "fr":
			return "Rencontre d'une situation mystérieuse et inconnue. S'il te plaît, réessaie plus tard~"
		case "ru":
			return "Произошло что-то загадочное и непонятное. Пожалуйста, попробуй позже~"
		case "es":
			return "Se ha producido una situación mysterious y desconocida. Por favor, inténtalo de nuevo más tarde~"
		default:
			return "Encountered an unknown mysterious situation. Please try again later~"
		}
	}
}

func getErrorDescription(lang string, status int, text string) string {
	if status >= 400 && status <= 499 {
		switch lang {
		case "zh":
			return text + " — 请求未成功完成。"
		case "ar":
			return text + " — لم يكتمل الطلب بنجاح."
		case "fr":
			return text + " — la requête n'a pas pu aboutir."
		case "ru":
			return text + " — запрос не был успешно завершен."
		case "es":
			return text + " — la solicitud no se completó correctamente."
		default:
			return text + " — the request did not complete successfully."
		}
	} else if status >= 500 && status <= 599 {
		switch lang {
		case "zh":
			return text + " — 服务器无法完成该请求。"
		case "ar":
			return text + " — لم يتمكن الخادم من إكمال الطلب."
		case "fr":
			return text + " — le serveur n'a pas pu traiter la requête."
		case "ru":
			return text + " — сервер не смог выполнить запрос."
		case "es":
			return text + " — el servidor no pudo completar la solicitud."
		default:
			return text + " — the server could not complete the request."
		}
	} else {
		switch lang {
		case "zh":
			return text + " — 请求以非预期状态结束。"
		case "ar":
			return text + " — انتهى الطلب بحالة غير متوقعة."
		case "fr":
			return text + " — La requête s'est terminée avec un statut inattendu."
		case "ru":
			return text + " — Запрос завершился с неожиданным статусом."
		case "es":
			return text + " — La solicitud finalizó con un estado inesperado."
		default:
			return text + " — The request ended with an unexpected status."
		}
	}
}

