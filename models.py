from django.db import models

# Create your models here.
class Fail2BanConfig(models.Model):
    """
    Model to store Fail2Ban configuration for domains
    """
    domain = models.CharField(max_length=255, unique=True)
    max_retries = models.IntegerField(default=30)
    find_time = models.IntegerField(default=60)  # in seconds
    ban_time = models.IntegerField(default=300)  # in seconds
    status_codes = models.CharField(max_length=255, default="401,403,404,500")
    ip_whitelist = models.TextField(blank=True, default="")
    
    def __str__(self):
        return f"Fail2Ban Config for {self.domain}"
        
    def get_whitelist_as_list(self):
        """
        Returns the whitelist as a list of IPs
        """
        if not self.ip_whitelist:
            return []
        return [ip.strip() + "/32" for ip in self.ip_whitelist.split(',') if ip.strip()]
