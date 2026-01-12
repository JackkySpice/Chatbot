.class public abstract Landroidx/appcompat/view/menu/tg;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final a:Landroidx/appcompat/view/menu/co0;

.field public static b:Landroidx/appcompat/view/menu/co0$b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "android.app.ContextImpl"

    invoke-static {v0}, Landroidx/appcompat/view/menu/co0;->w(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/tg;->a:Landroidx/appcompat/view/menu/co0;

    const-string v1, "mOpPackageName"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/co0;->e(Ljava/lang/String;)Landroidx/appcompat/view/menu/co0$b;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/tg;->b:Landroidx/appcompat/view/menu/co0$b;

    return-void
.end method
