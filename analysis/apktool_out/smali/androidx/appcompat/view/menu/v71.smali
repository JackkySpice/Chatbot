.class public abstract Landroidx/appcompat/view/menu/v71;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$b;

.field public static c:Landroidx/appcompat/view/menu/co0$b;

.field public static d:Landroidx/appcompat/view/menu/co0$b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "android.net.wifi.WifiInfo"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/v71;->a:Landroidx/appcompat/view/menu/co0;

    const-string v1, "mBSSID"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/v71;->b:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mMacAddress"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v1

    sput-object v1, Landroidx/appcompat/view/menu/v71;->c:Landroidx/appcompat/view/menu/co0$b;

    const-string v1, "mWifiSsid"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/v71;->d:Landroidx/appcompat/view/menu/co0$b;

    return-void
.end method
