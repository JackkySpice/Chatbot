.class public final Landroidx/appcompat/view/menu/r41;
.super Landroidx/appcompat/view/menu/ew0;
.source "SourceFile"


# instance fields
.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/String;

.field public final d:Landroidx/appcompat/view/menu/a51;

.field public final e:Landroidx/appcompat/view/menu/ia0;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/String;Landroidx/appcompat/view/menu/a51;Landroidx/appcompat/view/menu/ia0;)V
    .locals 1

    const-string v0, "value"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "tag"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "verificationMode"

    invoke-static {p3, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "logger"

    invoke-static {p4, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Landroidx/appcompat/view/menu/ew0;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/r41;->b:Ljava/lang/Object;

    iput-object p2, p0, Landroidx/appcompat/view/menu/r41;->c:Ljava/lang/String;

    iput-object p3, p0, Landroidx/appcompat/view/menu/r41;->d:Landroidx/appcompat/view/menu/a51;

    iput-object p4, p0, Landroidx/appcompat/view/menu/r41;->e:Landroidx/appcompat/view/menu/ia0;

    return-void
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/r41;->b:Ljava/lang/Object;

    return-object v0
.end method

.method public c(Ljava/lang/String;Landroidx/appcompat/view/menu/jw;)Landroidx/appcompat/view/menu/ew0;
    .locals 6

    const-string v0, "message"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "condition"

    invoke-static {p2, v0}, Landroidx/appcompat/view/menu/x50;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/r41;->b:Ljava/lang/Object;

    invoke-interface {p2, v0}, Landroidx/appcompat/view/menu/jw;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-eqz p2, :cond_0

    move-object p2, p0

    goto :goto_0

    :cond_0
    new-instance p2, Landroidx/appcompat/view/menu/wq;

    iget-object v1, p0, Landroidx/appcompat/view/menu/r41;->b:Ljava/lang/Object;

    iget-object v2, p0, Landroidx/appcompat/view/menu/r41;->c:Ljava/lang/String;

    iget-object v4, p0, Landroidx/appcompat/view/menu/r41;->e:Landroidx/appcompat/view/menu/ia0;

    iget-object v5, p0, Landroidx/appcompat/view/menu/r41;->d:Landroidx/appcompat/view/menu/a51;

    move-object v0, p2

    move-object v3, p1

    invoke-direct/range {v0 .. v5}, Landroidx/appcompat/view/menu/wq;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Landroidx/appcompat/view/menu/ia0;Landroidx/appcompat/view/menu/a51;)V

    :goto_0
    return-object p2
.end method
