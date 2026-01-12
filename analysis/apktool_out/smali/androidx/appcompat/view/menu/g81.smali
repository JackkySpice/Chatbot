.class public final Landroidx/appcompat/view/menu/g81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/c81;


# instance fields
.field public final b:Landroidx/appcompat/view/menu/y91;

.field public final c:Landroidx/appcompat/view/menu/x71;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/y91;Landroidx/appcompat/view/menu/x71;)V
    .locals 1

    const-string v0, "windowMetricsCalculator"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "windowBackend"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/g81;->b:Landroidx/appcompat/view/menu/y91;

    iput-object p2, p0, Landroidx/appcompat/view/menu/g81;->c:Landroidx/appcompat/view/menu/x71;

    return-void
.end method

.method public static final synthetic b(Landroidx/appcompat/view/menu/g81;)Landroidx/appcompat/view/menu/x71;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/g81;->c:Landroidx/appcompat/view/menu/x71;

    return-object p0
.end method


# virtual methods
.method public a(Landroid/app/Activity;)Landroidx/appcompat/view/menu/ws;
    .locals 2

    const-string v0, "activity"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Landroidx/appcompat/view/menu/g81$a;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Landroidx/appcompat/view/menu/g81$a;-><init>(Landroidx/appcompat/view/menu/g81;Landroid/app/Activity;Landroidx/appcompat/view/menu/wg;)V

    invoke-static {v0}, Landroidx/appcompat/view/menu/ys;->a(Landroidx/appcompat/view/menu/xw;)Landroidx/appcompat/view/menu/ws;

    move-result-object p1

    invoke-static {}, Landroidx/appcompat/view/menu/em;->c()Landroidx/appcompat/view/menu/na0;

    move-result-object v0

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/ys;->d(Landroidx/appcompat/view/menu/ws;Landroidx/appcompat/view/menu/jh;)Landroidx/appcompat/view/menu/ws;

    move-result-object p1

    return-object p1
.end method
