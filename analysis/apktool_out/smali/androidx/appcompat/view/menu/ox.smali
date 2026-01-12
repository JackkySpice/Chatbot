.class public Landroidx/appcompat/view/menu/ox;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/uw0;


# instance fields
.field public final a:Landroidx/appcompat/view/menu/p41;

.field public final b:Landroidx/appcompat/view/menu/xy0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/p41;Landroidx/appcompat/view/menu/xy0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ox;->a:Landroidx/appcompat/view/menu/p41;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ox;->b:Landroidx/appcompat/view/menu/xy0;

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/wh0;)Z
    .locals 4

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->k()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ox;->a:Landroidx/appcompat/view/menu/p41;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/p41;->f(Landroidx/appcompat/view/menu/wh0;)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ox;->b:Landroidx/appcompat/view/menu/xy0;

    invoke-static {}, Landroidx/appcompat/view/menu/o50;->a()Landroidx/appcompat/view/menu/o50$a;

    move-result-object v1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->b()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Landroidx/appcompat/view/menu/o50$a;->b(Ljava/lang/String;)Landroidx/appcompat/view/menu/o50$a;

    move-result-object v1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->c()J

    move-result-wide v2

    invoke-virtual {v1, v2, v3}, Landroidx/appcompat/view/menu/o50$a;->d(J)Landroidx/appcompat/view/menu/o50$a;

    move-result-object v1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/wh0;->h()J

    move-result-wide v2

    invoke-virtual {v1, v2, v3}, Landroidx/appcompat/view/menu/o50$a;->c(J)Landroidx/appcompat/view/menu/o50$a;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/o50$a;->a()Landroidx/appcompat/view/menu/o50;

    move-result-object p1

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/xy0;->c(Ljava/lang/Object;)V

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public b(Ljava/lang/Exception;)Z
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ox;->b:Landroidx/appcompat/view/menu/xy0;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/xy0;->d(Ljava/lang/Exception;)Z

    const/4 p1, 0x1

    return p1
.end method
