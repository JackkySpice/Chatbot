.class public final Landroidx/appcompat/view/menu/yf0$g;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/yf0;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "g"
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/yf0$g;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/yf0$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/yf0$g;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/yf0$g;->a:Landroidx/appcompat/view/menu/yf0$g;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/hw;Landroidx/appcompat/view/menu/hw;)Landroid/window/OnBackInvokedCallback;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroidx/appcompat/view/menu/jw;",
            "Landroidx/appcompat/view/menu/jw;",
            "Landroidx/appcompat/view/menu/hw;",
            "Landroidx/appcompat/view/menu/hw;",
            ")",
            "Landroid/window/OnBackInvokedCallback;"
        }
    .end annotation

    const-string v0, "onBackStarted"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onBackProgressed"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onBackInvoked"

    invoke-static {p3, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onBackCancelled"

    invoke-static {p4, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/appcompat/view/menu/yf0$g$a;

    invoke-direct {v0, p1, p2, p3, p4}, Landroidx/appcompat/view/menu/yf0$g$a;-><init>(Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/jw;Landroidx/appcompat/view/menu/hw;Landroidx/appcompat/view/menu/hw;)V

    return-object v0
.end method
