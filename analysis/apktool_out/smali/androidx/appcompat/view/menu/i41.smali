.class public abstract Landroidx/appcompat/view/menu/i41;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$e;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "android.os.UserHandle"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/i41;->a:Landroidx/appcompat/view/menu/co0;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Class;

    const-string v2, "myUserId"

    invoke-virtual {v0, v2, v1}, Landroidx/appcompat/view/menu/co0;->z(Ljava/lang/String;[Ljava/lang/Class;)Landroidx/appcompat/view/menu/co0$e;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/i41;->b:Landroidx/appcompat/view/menu/co0$e;

    return-void
.end method
