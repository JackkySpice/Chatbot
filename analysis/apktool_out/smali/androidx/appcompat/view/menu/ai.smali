.class public Landroidx/appcompat/view/menu/ai;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/sp;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/x6;Landroidx/appcompat/view/menu/l50;I)I
    .locals 0

    iget-object p2, p1, Landroidx/appcompat/view/menu/x6;->m:Landroidx/appcompat/view/menu/t6;

    iget-object p2, p2, Landroidx/appcompat/view/menu/t6;->y:Ljava/lang/String;

    invoke-static {p2}, Landroidx/appcompat/view/menu/hv0;->b(Ljava/lang/String;)Ljava/io/File;

    move-result-object p2

    invoke-static {p2}, Landroidx/appcompat/view/menu/pr;->d(Ljava/io/File;)I

    iget-object p2, p1, Landroidx/appcompat/view/menu/x6;->m:Landroidx/appcompat/view/menu/t6;

    iget-object p2, p2, Landroidx/appcompat/view/menu/t6;->y:Ljava/lang/String;

    invoke-static {p2}, Landroidx/appcompat/view/menu/hv0;->b(Ljava/lang/String;)Ljava/io/File;

    move-result-object p2

    invoke-static {p2}, Landroidx/appcompat/view/menu/pr;->g(Ljava/io/File;)V

    iget-object p1, p1, Landroidx/appcompat/view/menu/x6;->m:Landroidx/appcompat/view/menu/t6;

    iget-object p1, p1, Landroidx/appcompat/view/menu/t6;->y:Ljava/lang/String;

    invoke-static {p1}, Landroidx/appcompat/view/menu/hv0;->c(Ljava/lang/String;)Ljava/io/File;

    move-result-object p1

    invoke-static {p1}, Landroidx/appcompat/view/menu/pr;->g(Ljava/io/File;)V

    const/4 p1, 0x0

    return p1
.end method
