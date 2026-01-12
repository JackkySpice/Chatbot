.class public Landroidx/appcompat/view/menu/s71;
.super Landroidx/appcompat/view/menu/nb;
.source "SourceFile"


# instance fields
.field public final p:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Landroidx/appcompat/view/menu/nb;-><init>()V

    sget-object v0, Landroidx/appcompat/view/menu/r71;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/co0$b;->a()Ljava/lang/Object;

    move-result-object v0

    iput-object v0, p0, Landroidx/appcompat/view/menu/s71;->p:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public h()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/s71;->p:Ljava/lang/Object;

    return-object v0
.end method

.method public i(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    sget-object p1, Landroidx/appcompat/view/menu/r71;->b:Landroidx/appcompat/view/menu/co0$b;

    invoke-virtual {p1, p2}, Landroidx/appcompat/view/menu/co0$b;->c(Ljava/lang/Object;)V

    return-void
.end method
