# EmailVV
Email Verify &amp; Validate - Class

## Example using

```php
$evv = new EmailVV("test@gmail.com","fatihmertdogancan@hotmail.com");
```

## Regexp Control (Standart PHP Filter) @return bool

```php
$evv->validate();
```

## Whois Domain Control  @return bool

```php
$evv->is_available_domain();
```

## Verify, Default port is 25  @return bool
```php
$evv->verify(); 
```

## You can change port, example: smtp

```php
$evv->change_port("SMTP");		// [SMTP,GMAIL,MYNET,MSN,LIVE,HOTMAIL,YAHOO,POP3,IMAP]
$evv->verify(); //SMTP verify
```

## or Default port set
```php
$evv->set_port(587);
$evv->verify(); //SMTP verify
```

## Validate RFCs 822, 2822, 5322
```php
$evv->is_rfc822();
```
